package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
const version = "0.2.0"

type config struct {
	listenAddr      string
	publicChatURL   string
	rateLimitPerMin int
	enrollStore     string
	pepper          string
	mm              mattermost.Config
	policy          core.Policy
}

type server struct {
	cfg  config
	svc  *core.Service
	port core.ProviderPort
	log  *slog.Logger
	mu   sync.Mutex
	hits map[string][]time.Time
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
	log.Info("listening", "version", version, "addr", cfg.listenAddr, "mattermost", cfg.mm.URL,
		"shared_secret", cfg.policy.SharedSecret != "", "enrollment", s.svc.Store != nil)
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
		listenAddr:      env("LISTEN_ADDR", ":8080"),
		publicChatURL:   strings.TrimRight(env("PUBLIC_CHAT_URL", "https://chat.bgl.dembach.org"), "/"),
		rateLimitPerMin: 30,
		enrollStore:     env("ENROLLMENT_STORE", "/data/enrollments.json"),
		pepper:          env("ENROLLMENT_PEPPER", ""),
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
	if envBool(getenv, "ALLOW_SHARED_SECRET", true) {
		cfg.policy.SharedSecret = env("REGISTRATION_SECRET", "")
	}
	p := cfg.policy
	if p.DefaultTTL > p.MaxTTL {
		errs = append(errs, errors.New("ENROLLMENT_DEFAULT_TTL exceeds ENROLLMENT_MAX_TTL"))
	}
	if p.DefaultMaxBots < 1 || p.DefaultMaxBots > p.MaxBotsLimit {
		errs = append(errs, errors.New("ENROLLMENT_DEFAULT_MAX_BOTS must be 1..ENROLLMENT_MAX_BOTS_LIMIT"))
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

func newServer(cfg config, client *http.Client, log *slog.Logger) (*server, error) {
	port := &mattermost.Adapter{Cfg: cfg.mm, Client: client, Log: log}
	svc := &core.Service{Provider: port, Policy: cfg.policy, Log: log}
	if len(cfg.mm.CommandTokens) > 0 {
		st, err := core.OpenStore(cfg.enrollStore, []byte(cfg.pepper))
		if err != nil {
			return nil, err
		}
		svc.Store = st
	}
	return &server{cfg: cfg, svc: svc, port: port, log: log, hits: map[string][]time.Time{}}, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /register/v1/agents", s.handleRegister)
	mux.HandleFunc("DELETE /register/v1/agents/{name}", s.handleUnregister)
	if s.svc.Store != nil {
		mux.HandleFunc("POST /register/v1/command", s.handleCommand)
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
	if !s.allowRate(clientIP(r)) {
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
	})
}

func (s *server) handleUnregister(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate(clientIP(r)) {
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
	if !s.allowRate(clientIP(r)) {
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

func (s *server) allowRate(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	cut := now.Add(-time.Minute)
	var kept []time.Time
	for _, t := range s.hits[ip] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= s.cfg.rateLimitPerMin {
		s.hits[ip] = kept
		return false
	}
	s.hits[ip] = append(kept, now)
	return true
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, _ := strings.Cut(r.RemoteAddr, ":")
	if host == "" {
		return r.RemoteAddr
	}
	return host
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
