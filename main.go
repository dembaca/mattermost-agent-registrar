package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dembaca/mattermost-agent-registrar/internal/core"
	"github.com/dembaca/mattermost-agent-registrar/internal/mattermost"
)

// version is the release; CHANGELOG.md and the image tag in CI follow it.
const version = "0.7.1"

// pruneEvery is how often the token store is pruned while running.
const pruneEvery = time.Hour

type config struct {
	listenAddr      string
	publicChatURL   string
	rateLimitPerMin int
	// modeRateLimitPerMin is the own bucket of GET /register/v1/modes/…, so
	// agents polling their channel's mode never starve registrations.
	modeRateLimitPerMin int
	// mandateRateLimitPerMin is the own bucket of GET /register/v1/mandates/….
	mandateRateLimitPerMin int
	// attestationRateLimitPerMin is the own bucket of GET /register/v1/attestations/….
	attestationRateLimitPerMin int
	// trustedProxyHops is how many proxies in front of the registrar append to
	// X-Forwarded-For; the entry that many places from the right is the client.
	// 0: the header is ignored.
	trustedProxyHops int
	attestationStore string
	enrollStore      string
	pepper           string
	modeTokens       []string // verification tokens of the mode command; none: no command
	modeStore        string
	mandateTokens    []string // verification tokens of the mandate command; none: no command
	mandateStore     string
	mm               mattermost.Config
	policy           core.Policy
	attestor         *core.Attestor // nil: no attestation, no mode records
}

type server struct {
	cfg      config
	svc      *core.Service
	port     core.ProviderPort
	modePort core.ProviderPort // verifies the mode command's tokens; nil without them
	log      *slog.Logger
	rate     *limiter
	modeRate *limiter
	// mandatePort verifies the mandate command's tokens; nil without them.
	mandatePort     core.ProviderPort
	mandateRate     *limiter
	attestationRate *limiter
}

// limiter is a per-IP sliding window of one minute.
type limiter struct {
	perMin int
	mu     sync.Mutex
	hits   map[string][]time.Time
}

func newLimiter(perMin int) *limiter {
	return &limiter{perMin: perMin, hits: map[string][]time.Time{}}
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	if cfg.mm.Token == "PENDING_REPLACE_AFTER_MM_BOOTSTRAP" {
		log.Warn("MATTERMOST_TOKEN is placeholder; register/unregister will fail until a real admin PAT is set")
	}
	s, err := newServer(cfg, &http.Client{Timeout: 30 * time.Second}, log)
	if err != nil {
		log.Error("startup", "err", err)
		os.Exit(1)
	}
	if cfg.attestor != nil {
		log.Info("attestation on", "kid", cfg.attestor.Kid(), "ttl", cfg.attestor.TTL.String(),
			"mode_command", s.modePort != nil, "mandate_command", s.mandatePort != nil)
	}
	log.Info("listening", "version", version, "addr", cfg.listenAddr, "mattermost", cfg.mm.URL,
		"shared_secret", cfg.policy.SharedSecret != "", "enrollment", s.svc.Store != nil)
	if s.svc.Store != nil {
		s.svc.PruneTokens()
		go func() {
			for range time.Tick(pruneEvery) {
				s.svc.PruneTokens()
			}
		}()
	}
	if err := http.ListenAndServe(cfg.listenAddr, s.routes()); err != nil {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

// loadConfig reads the environment. Every name and limit is a setting; the
// defaults only fill in what the operator left out.
func loadConfig(getenv func(string) string) (config, error) {
	env := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	var errs []error
	need := func(k string) string {
		v := env(k, "")
		if v == "" {
			errs = append(errs, fmt.Errorf("missing env %s", k))
		}
		return v
	}
	num := func(k string, def int) int {
		v := env(k, "")
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			errs = append(errs, fmt.Errorf("%s: not a number: %q", k, v))
			return def
		}
		return n
	}
	ttl := func(k, def string) time.Duration {
		d, err := core.ParseTTL(env(k, def))
		if err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("%s: not a duration like 30d or 12h", k))
		}
		return d
	}
	cfg := config{
		listenAddr:                 env("LISTEN_ADDR", ":8080"),
		publicChatURL:              strings.TrimRight(env("PUBLIC_CHAT_URL", "https://chat.bgl.dembach.org"), "/"),
		rateLimitPerMin:            30,
		modeRateLimitPerMin:        120,
		mandateRateLimitPerMin:     120,
		attestationRateLimitPerMin: 120,
		trustedProxyHops:           num("TRUSTED_PROXY_HOPS", 1),
		attestationStore:           env("ATTESTATION_STORE", "/data/attestations.json"),
		enrollStore:                env("ENROLLMENT_STORE", "/data/enrollments.json"),
		pepper:                     env("ENROLLMENT_PEPPER", ""),
		modeTokens:                 splitList(env("MODE_COMMAND_TOKEN", "")),
		modeStore:                  env("MODE_STORE", "/data/modes.json"),
		mandateTokens:              splitList(env("MANDATE_COMMAND_TOKEN", "")),
		mandateStore:               env("MANDATE_STORE", "/data/mandates.json"),
		mm: mattermost.Config{
			URL:              strings.TrimRight(need("MATTERMOST_URL"), "/"),
			Token:            need("MATTERMOST_TOKEN"),
			Team:             env("DEFAULT_TEAM_NAME", "ai-agents"),
			HideBotDM:        envBool(getenv, "HIDE_BOT_DM", true),
			CommandTokens:    splitList(env("SLASH_COMMAND_TOKEN", "")),
			TokenDescription: "agent-registrar",
		},
		policy: core.Policy{
			BotPrefix:        env("BOT_USERNAME_PREFIX", "agent-"),
			DefaultChannel:   env("DEFAULT_CHANNEL_NAME", "agents"),
			MaxTrusted:       num("MAX_TRUSTED", 10),
			DefaultTTL:       ttl("ENROLLMENT_DEFAULT_TTL", "30d"),
			MaxTTL:           ttl("ENROLLMENT_MAX_TTL", "90d"),
			DefaultMaxBots:   num("ENROLLMENT_DEFAULT_MAX_BOTS", 3),
			MaxBotsLimit:     num("ENROLLMENT_MAX_BOTS_LIMIT", 20),
			MaxTokensPerUser: num("ENROLLMENT_MAX_TOKENS_PER_USER", 20),
		},
	}
	// 0 is allowed here: prune revoked and expired tokens at the next pass.
	if d, err := core.ParseTTL(env("ENROLLMENT_RETENTION", "30d")); err != nil || d < 0 {
		errs = append(errs, errors.New("ENROLLMENT_RETENTION: not a duration like 30d or 12h (0 to prune at once)"))
	} else {
		cfg.policy.TokenRetention = d
	}
	if envBool(getenv, "ALLOW_SHARED_SECRET", true) {
		cfg.policy.SharedSecret = env("REGISTRATION_SECRET", "")
	}
	cfg.attestor = loadAttestor(env, ttl, &errs)
	p := cfg.policy
	if p.DefaultTTL > p.MaxTTL {
		errs = append(errs, errors.New("ENROLLMENT_DEFAULT_TTL exceeds ENROLLMENT_MAX_TTL"))
	}
	if p.DefaultMaxBots < 1 || p.DefaultMaxBots > p.MaxBotsLimit {
		errs = append(errs, errors.New("ENROLLMENT_DEFAULT_MAX_BOTS must be 1..ENROLLMENT_MAX_BOTS_LIMIT"))
	}
	if len(cfg.modeTokens) > 0 && env("ATTESTATION_KEY", "") == "" && env("ATTESTATION_KEY_FILE", "") == "" {
		errs = append(errs, errors.New("MODE_COMMAND_TOKEN needs ATTESTATION_KEY or ATTESTATION_KEY_FILE: mode records are signed"))
	}
	if len(cfg.mandateTokens) > 0 && env("ATTESTATION_KEY", "") == "" && env("ATTESTATION_KEY_FILE", "") == "" {
		errs = append(errs, errors.New("MANDATE_COMMAND_TOKEN needs ATTESTATION_KEY or ATTESTATION_KEY_FILE: mandate records are signed"))
	}
	enroll := len(cfg.mm.CommandTokens) > 0
	switch {
	case enroll && len(cfg.pepper) < 32:
		errs = append(errs, errors.New("SLASH_COMMAND_TOKEN needs ENROLLMENT_PEPPER (at least 32 characters)"))
	case !enroll && cfg.pepper != "":
		errs = append(errs, errors.New("ENROLLMENT_PEPPER is set but SLASH_COMMAND_TOKEN is not"))
	}
	if !enroll && p.SharedSecret == "" {
		errs = append(errs, errors.New("no way to register: set REGISTRATION_SECRET (with ALLOW_SHARED_SECRET not false) or SLASH_COMMAND_TOKEN and ENROLLMENT_PEPPER"))
	}
	return cfg, errors.Join(errs...)
}

// loadAttestor reads ATTESTATION_KEY or ATTESTATION_KEY_FILE and
// ATTESTATION_TTL. No key means no attestation. Errors never carry the key.
func loadAttestor(env func(k, def string) string, ttl func(k, def string) time.Duration, errs *[]error) *core.Attestor {
	key, file := env("ATTESTATION_KEY", ""), env("ATTESTATION_KEY_FILE", "")
	d := ttl("ATTESTATION_TTL", "30d")
	if key != "" && file != "" {
		*errs = append(*errs, errors.New("set ATTESTATION_KEY or ATTESTATION_KEY_FILE, not both"))
		return nil
	}
	name := "ATTESTATION_KEY"
	if file != "" {
		name = "ATTESTATION_KEY_FILE"
		b, err := os.ReadFile(file)
		if err != nil {
			*errs = append(*errs, fmt.Errorf("ATTESTATION_KEY_FILE: cannot read %s", file))
			return nil
		}
		key = strings.TrimSpace(string(b))
	}
	if key == "" {
		return nil
	}
	seed, err := core.ParseSeed(key)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %v", name, err))
		return nil
	}
	if d <= 0 {
		return nil // the TTL error is already collected
	}
	a, err := core.NewAttestor(seed, d)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %v", name, err))
		return nil
	}
	return a
}

func newServer(cfg config, client *http.Client, log *slog.Logger) (*server, error) {
	port := &mattermost.Adapter{Cfg: cfg.mm, Client: client, Log: log}
	svc := &core.Service{Provider: port, Policy: cfg.policy, Log: log, Attestor: cfg.attestor}
	if len(cfg.mm.CommandTokens) > 0 {
		st, err := core.OpenStore(cfg.enrollStore, []byte(cfg.pepper))
		if err != nil {
			return nil, err
		}
		svc.Store = st
	}
	s := &server{cfg: cfg, svc: svc, port: port, log: log,
		rate: newLimiter(cfg.rateLimitPerMin), modeRate: newLimiter(cfg.modeRateLimitPerMin),
		mandateRate:     newLimiter(cfg.mandateRateLimitPerMin),
		attestationRate: newLimiter(cfg.attestationRateLimitPerMin)}
	if cfg.attestor != nil {
		// The store is read for GET /register/v1/modes/… even without the
		// command, so modes set earlier stay published.
		ms, err := core.OpenModeStore(cfg.modeStore)
		if err != nil {
			return nil, err
		}
		svc.Modes = ms
		if len(cfg.modeTokens) > 0 {
			// The same adapter, verifying the mode command's own tokens.
			mcfg := cfg.mm
			mcfg.CommandTokens = cfg.modeTokens
			s.modePort = &mattermost.Adapter{Cfg: mcfg, Client: client, Log: log}
		}
		// Likewise for GET /register/v1/mandates/….
		mds, err := core.OpenMandateStore(cfg.mandateStore)
		if err != nil {
			return nil, err
		}
		svc.Mandates = mds
		// And for GET /register/v1/attestations/…, whichever way a bot registers.
		cs, err := core.OpenClaimStore(cfg.attestationStore)
		if err != nil {
			return nil, err
		}
		svc.Claims = cs
		if len(cfg.mandateTokens) > 0 {
			mcfg := cfg.mm
			mcfg.CommandTokens = cfg.mandateTokens
			s.mandatePort = &mattermost.Adapter{Cfg: mcfg, Client: client, Log: log}
		}
	}
	return s, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /register/v1/agents", s.handleRegister)
	mux.HandleFunc("DELETE /register/v1/agents/{name}", s.handleUnregister)
	mux.HandleFunc("GET /register/v1/keys", s.handleKeys)
	mux.HandleFunc("GET /register/v1/version", s.handleVersion)
	if s.svc.Store != nil {
		mux.HandleFunc("POST /register/v1/command", s.handleCommand)
	}
	if s.svc.Modes != nil {
		mux.HandleFunc("GET /register/v1/modes/{channel_id}", s.handleMode)
	}
	if s.modePort != nil {
		mux.HandleFunc("POST /register/v1/mode", s.handleModeCommand)
	}
	if s.svc.Mandates != nil {
		mux.HandleFunc("GET /register/v1/mandates/{channel_id}", s.handleMandate)
	}
	if s.mandatePort != nil {
		mux.HandleFunc("POST /register/v1/mandate", s.handleMandateCommand)
	}
	if s.svc.Claims != nil {
		mux.HandleFunc("GET /register/v1/attestations/{bot_id}", s.handleAttestation)
	}
	return mux
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

type registerResp struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	BotToken string `json:"bot_token"`
	UserID   string `json:"user_id"`
	Owner    string `json:"owner,omitempty"` // bound owner; absent for unbound bots
	// Attestation is the signed owner claim; absent without ATTESTATION_KEY.
	Attestation string `json:"attestation,omitempty"`
}

// fail maps a core error kind to a status; the message after the kind is
// meant for the caller.
func (s *server) fail(w http.ResponseWriter, err error) {
	status, msg := http.StatusInternalServerError, "internal error"
	switch {
	case errors.Is(err, core.ErrBadRequest):
		status, msg = http.StatusBadRequest, err.Error()
	case errors.Is(err, core.ErrUnauthorized):
		status, msg = http.StatusUnauthorized, err.Error()
	case errors.Is(err, core.ErrForbidden):
		status, msg = http.StatusForbidden, err.Error()
	case errors.Is(err, core.ErrConflict):
		status, msg = http.StatusConflict, err.Error()
	case errors.Is(err, core.ErrUpstream):
		// "provider error: create bot: <detail>" -> "create bot failed"; the detail goes to the log only.
		status = http.StatusBadGateway
		msg = strings.SplitN(strings.TrimPrefix(err.Error(), core.ErrUpstream.Error()+": "), ":", 2)[0] + " failed"
	}
	if status >= 500 {
		s.log.Error("request failed", "err", err)
	}
	http.Error(w, msg, status)
}

func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	cred := bearer(r)
	if cred == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !s.allowRate(s.clientIP(r)) {
		http.Error(w, "rate limit", http.StatusTooManyRequests)
		return
	}
	var req core.RegisterRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	reg, err := s.svc.Register(r.Context(), cred, req)
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(registerResp{
		URL:      s.cfg.publicChatURL,
		Username: reg.Agent.Username,
		BotToken: reg.Credential,
		UserID:   reg.Agent.ID,
		Owner:    reg.Owner,

		Attestation: reg.Attestation,
	})
}

// handleKeys publishes the attestation public key (RFC 8037 JWK set). Public;
// empty without a key.
func (s *server) handleKeys(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate(s.clientIP(r)) {
		http.Error(w, "rate limit", http.StatusTooManyRequests)
		return
	}
	keys := []core.JWK{}
	if s.cfg.attestor != nil {
		keys = append(keys, s.cfg.attestor.Key())
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=300")
	_ = json.NewEncoder(w).Encode(struct {
		Keys []core.JWK `json:"keys"`
	}{keys})
}

// handleVersion tells which registrar version is deployed. Public, same rate
// limit as the keys.
func (s *server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate(s.clientIP(r)) {
		http.Error(w, "rate limit", http.StatusTooManyRequests)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Version string `json:"version"`
	}{version})
}

func (s *server) handleUnregister(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate(s.clientIP(r)) {
		http.Error(w, "rate limit", http.StatusTooManyRequests)
		return
	}
	if err := s.svc.Unregister(r.Context(), bearer(r), r.PathValue("name")); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleCommand serves the slash command (/agent-token or whatever trigger
// the operator chose). Every answer is private to the caller.
func (s *server) handleCommand(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if !s.allowRate(s.clientIP(r)) {
		http.Error(w, "rate limit", http.StatusTooManyRequests)
		return
	}
	inv, err := s.port.VerifyInvocation(r)
	if err != nil {
		if errors.Is(err, core.ErrForbidden) {
			s.port.ReplyPrivate(w, inv, strings.TrimPrefix(err.Error(), core.ErrForbidden.Error()+": "))
			return
		}
		s.fail(w, err)
		return
	}
	s.port.ReplyPrivate(w, inv, s.svc.Command(r.Context(), inv))
}

// handleModeCommand serves the mode command (/agent-mode or whatever trigger
// the operator chose), verified with MODE_COMMAND_TOKEN. Every answer is
// private to the caller.
func (s *server) handleModeCommand(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if !s.allowRate(s.clientIP(r)) {
		http.Error(w, "rate limit", http.StatusTooManyRequests)
		return
	}
	inv, err := s.modePort.VerifyInvocation(r)
	if err != nil {
		if errors.Is(err, core.ErrForbidden) {
			s.modePort.ReplyPrivate(w, inv, strings.TrimPrefix(err.Error(), core.ErrForbidden.Error()+": "))
			return
		}
		s.fail(w, err)
		return
	}
	s.modePort.ReplyPrivate(w, inv, s.svc.ModeCommand(r.Context(), inv))
}

// handleMode publishes a channel's ask mode as a signed record, signed fresh
// for each request. Public like the keys: the bus verifies the record against
// its pinned key and never trusts this endpoint. Its own rate bucket.
func (s *server) handleMode(w http.ResponseWriter, r *http.Request) {
	if !s.modeRate.allow(s.clientIP(r)) {
		http.Error(w, "rate limit", http.StatusTooManyRequests)
		return
	}
	rec, err := s.svc.ModeRecord(r.PathValue("channel_id"))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case errors.Is(err, core.ErrBadRequest):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid channel id"})
	case errors.Is(err, core.ErrNoMode):
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "no mode set"})
	case err != nil:
		s.log.Error("sign mode record", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
	default:
		_ = json.NewEncoder(w).Encode(map[string]string{"record": rec})
	}
}

// handleMandateCommand serves the mandate command (/agent-mandate or whatever
// trigger the operator chose), verified with MANDATE_COMMAND_TOKEN. Every
// answer is private to the caller.
func (s *server) handleMandateCommand(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if !s.allowRate(s.clientIP(r)) {
		http.Error(w, "rate limit", http.StatusTooManyRequests)
		return
	}
	inv, err := s.mandatePort.VerifyInvocation(r)
	if err != nil {
		if errors.Is(err, core.ErrForbidden) {
			s.mandatePort.ReplyPrivate(w, inv, strings.TrimPrefix(err.Error(), core.ErrForbidden.Error()+": "))
			return
		}
		s.fail(w, err)
		return
	}
	s.mandatePort.ReplyPrivate(w, inv, s.svc.MandateCommand(r.Context(), inv))
}

// handleMandate publishes a channel's mandate as a signed record, signed fresh
// for each request. Public like the modes; its own rate bucket.
func (s *server) handleMandate(w http.ResponseWriter, r *http.Request) {
	if !s.mandateRate.allow(s.clientIP(r)) {
		http.Error(w, "rate limit", http.StatusTooManyRequests)
		return
	}
	rec, err := s.svc.MandateRecord(r.PathValue("channel_id"))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case errors.Is(err, core.ErrBadRequest):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid channel id"})
	case errors.Is(err, core.ErrNoMandate):
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "no mandate set"})
	case err != nil:
		s.log.Error("sign mandate record", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
	default:
		_ = json.NewEncoder(w).Encode(map[string]string{"record": rec})
	}
}

// handleAttestation publishes a bot's attestation, signed fresh for each
// request with a short expiry. Public like the modes and mandates; its own rate
// bucket. 404 with `no attestation` means none; any other failure is no 404.
func (s *server) handleAttestation(w http.ResponseWriter, r *http.Request) {
	if !s.attestationRate.allow(s.clientIP(r)) {
		http.Error(w, "rate limit", http.StatusTooManyRequests)
		return
	}
	rec, err := s.svc.AttestationRecord(r.Context(), r.PathValue("bot_id"))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case errors.Is(err, core.ErrBadRequest):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid bot id"})
	case errors.Is(err, core.ErrNoAttestation):
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "no attestation"})
	case errors.Is(err, core.ErrUpstream):
		s.log.Error("attestation record", "err", err)
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "lookup failed"})
	case err != nil:
		s.log.Error("sign attestation record", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
	default:
		_ = json.NewEncoder(w).Encode(map[string]string{"record": rec})
	}
}

func (s *server) allowRate(ip string) bool { return s.rate.allow(ip) }

func (l *limiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cut := now.Add(-time.Minute)
	var kept []time.Time
	for _, t := range l.hits[ip] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.perMin {
		l.hits[ip] = kept
		return false
	}
	l.hits[ip] = append(kept, now)
	return true
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

// clientIP is the address the rate buckets count. Each trusted proxy appends the
// peer it saw to X-Forwarded-For, so only entries from the right are the proxies'
// own; the left ones are whatever the client sent. With too few entries, or none,
// or with TRUSTED_PROXY_HOPS=0, the connection's own address counts.
func (s *server) clientIP(r *http.Request) string {
	if n := s.cfg.trustedProxyHops; n > 0 {
		var entries []string
		for _, h := range r.Header.Values("X-Forwarded-For") {
			entries = append(entries, strings.Split(h, ",")...)
		}
		if len(entries) >= n {
			if ip := strings.TrimSpace(entries[len(entries)-n]); ip != "" {
				return ip
			}
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envBool(getenv func(string) string, k string, def bool) bool {
	v := strings.TrimSpace(getenv(k))
	if v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}
