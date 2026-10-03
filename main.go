package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$`)

type config struct {
	listenAddr      string
	mmURL           string
	publicChatURL   string
	mmToken         string
	regSecret       string
	botPrefix       string
	defaultTeam     string
	defaultChannel  string
	hideBotDM       bool
	rateLimitPerMin int
}

type server struct {
	cfg    config
	client *http.Client
	log    *slog.Logger
	mu     sync.Mutex
	hits   map[string][]time.Time
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := config{
		listenAddr:      envOr("LISTEN_ADDR", ":8080"),
		mmURL:           strings.TrimRight(mustEnv("MATTERMOST_URL"), "/"),
		publicChatURL:   strings.TrimRight(envOr("PUBLIC_CHAT_URL", "https://chat.bgl.dembach.org"), "/"),
		mmToken:         mustEnv("MATTERMOST_TOKEN"),
		regSecret:       mustEnv("REGISTRATION_SECRET"),
		botPrefix:       envOr("BOT_USERNAME_PREFIX", "agent-"),
		defaultTeam:     envOr("DEFAULT_TEAM_NAME", "ai-agents"),
		defaultChannel:  envOr("DEFAULT_CHANNEL_NAME", "agents"),
		hideBotDM:       envBool("HIDE_BOT_DM", true),
		rateLimitPerMin: 30,
	}
	if cfg.mmToken == "" || cfg.mmToken == "PENDING_REPLACE_AFTER_MM_BOOTSTRAP" {
		log.Warn("MATTERMOST_TOKEN is placeholder; register/unregister will fail until a real admin PAT is set")
	}
	s := &server{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
		log:    log,
		hits:   map[string][]time.Time{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /register/v1/agents", s.handleRegister)
	mux.HandleFunc("DELETE /register/v1/agents/{name}", s.handleUnregister)
	log.Info("listening", "addr", cfg.listenAddr, "mattermost", cfg.mmURL)
	if err := http.ListenAndServe(cfg.listenAddr, mux); err != nil {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

type registerReq struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

type registerResp struct {
	URL       string `json:"url"`
	Username  string `json:"username"`
	BotToken  string `json:"bot_token"`
	UserID    string `json:"user_id"`
}

func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeRegistration(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !s.allowRate(clientIP(r)) {
		http.Error(w, "rate limit", http.StatusTooManyRequests)
		return
	}
	var req registerReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	name := strings.ToLower(strings.TrimSpace(req.Name))
	if !nameRE.MatchString(name) {
		http.Error(w, "invalid name (use 3-32 lowercase alnum/hyphen)", http.StatusBadRequest)
		return
	}
	username := s.cfg.botPrefix + name
	display := strings.TrimSpace(req.DisplayName)
	if display == "" {
		display = username
	}

	ctx := r.Context()
	if existing, err := s.getUserByUsername(ctx, username); err == nil && existing != nil {
		http.Error(w, "agent already registered", http.StatusConflict)
		return
	}

	bot, err := s.createBot(ctx, username, display)
	if err != nil {
		s.log.Error("create bot", "err", err, "username", username)
		http.Error(w, "create bot failed", http.StatusBadGateway)
		return
	}
	if s.cfg.hideBotDM {
		// Cosmetic: never fail registration if this fails.
		s.hideBotDirectChannel(ctx, bot.UserID)
	}
	token, err := s.createAccessToken(ctx, bot.UserID, "agent-registrar")
	if err != nil {
		s.log.Error("create token", "err", err, "user_id", bot.UserID)
		_ = s.disableBot(ctx, bot.UserID)
		http.Error(w, "create token failed", http.StatusBadGateway)
		return
	}
	if err := s.ensureTeamChannel(ctx, bot.UserID); err != nil {
		s.log.Warn("team/channel invite", "err", err, "user_id", bot.UserID)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(registerResp{
		URL:      s.cfg.publicChatURL,
		Username: username,
		BotToken: token,
		UserID:   bot.UserID,
	})
}

func (s *server) handleUnregister(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(strings.TrimSpace(r.PathValue("name")))
	if !nameRE.MatchString(name) {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	username := s.cfg.botPrefix + name
	auth := bearer(r)
	if auth == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	user, err := s.getUserByUsername(ctx, username)
	if err != nil || user == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	ok := false
	if auth == s.cfg.regSecret {
		ok = true
	} else if me, err := s.getMe(ctx, auth); err == nil && me != nil && me.ID == user.ID {
		ok = true
	}
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !s.allowRate(clientIP(r)) {
		http.Error(w, "rate limit", http.StatusTooManyRequests)
		return
	}

	_ = s.revokeAllTokens(ctx, user.ID)
	if err := s.disableBot(ctx, user.ID); err != nil {
		s.log.Error("disable bot", "err", err, "user_id", user.ID)
		http.Error(w, "disable failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) authorizeRegistration(r *http.Request) bool {
	return bearer(r) != "" && bearer(r) == s.cfg.regSecret
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

type mmUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

type mmBot struct {
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

type mmToken struct {
	Token string `json:"token"`
	ID    string `json:"id"`
}

func (s *server) createBot(ctx context.Context, username, display string) (*mmBot, error) {
	body := map[string]any{
		"username":     username,
		"display_name": display,
		"description":  "Registered via agent-registrar",
	}
	var bot mmBot
	if err := s.mmJSON(ctx, http.MethodPost, "/api/v4/bots", body, s.cfg.mmToken, &bot); err != nil {
		return nil, err
	}
	return &bot, nil
}

// hideBotDirectChannel hides the admin↔bot DM from the registrar account's sidebar.
//
// Mattermost CreateBot synchronously opens a DM with the creating user and posts the
// "add me to teams/channels" welcome message before returning the bot. That path also
// sets direct_channel_show=true for the creator. Setting the preference here (after
// createBot returns) therefore runs after that write — no delay is required. If a
// future Mattermost version posts the welcome async and the sidebar entry reappears,
// re-set the preference after the DM channel exists or after a short settle delay.
func (s *server) hideBotDirectChannel(ctx context.Context, botUserID string) {
	me, err := s.getMe(ctx, s.cfg.mmToken)
	if err != nil || me == nil || me.ID == "" {
		s.log.Warn("hide bot dm: get me", "err", err, "bot_user_id", botUserID)
		return
	}
	prefs := []mmPreference{{
		UserID:   me.ID,
		Category: "direct_channel_show",
		Name:     botUserID,
		Value:    "false",
	}}
	if err := s.mmJSON(ctx, http.MethodPut, "/api/v4/users/me/preferences", prefs, s.cfg.mmToken, nil); err != nil {
		s.log.Warn("hide bot dm", "err", err, "bot_user_id", botUserID, "admin_user_id", me.ID)
	}
}

type mmPreference struct {
	UserID   string `json:"user_id"`
	Category string `json:"category"`
	Name     string `json:"name"`
	Value    string `json:"value"`
}

func (s *server) createAccessToken(ctx context.Context, userID, description string) (string, error) {
	var tok mmToken
	err := s.mmJSON(ctx, http.MethodPost, "/api/v4/users/"+userID+"/tokens", map[string]string{
		"description": description,
	}, s.cfg.mmToken, &tok)
	if err != nil {
		return "", err
	}
	if tok.Token == "" {
		return "", errors.New("empty token")
	}
	return tok.Token, nil
}

func (s *server) getUserByUsername(ctx context.Context, username string) (*mmUser, error) {
	var u mmUser
	err := s.mmJSON(ctx, http.MethodGet, "/api/v4/users/username/"+username, nil, s.cfg.mmToken, &u)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (s *server) getMe(ctx context.Context, token string) (*mmUser, error) {
	var u mmUser
	if err := s.mmJSON(ctx, http.MethodGet, "/api/v4/users/me", nil, token, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *server) revokeAllTokens(ctx context.Context, userID string) error {
	var tokens []mmToken
	if err := s.mmJSON(ctx, http.MethodGet, "/api/v4/users/"+userID+"/tokens?per_page=200", nil, s.cfg.mmToken, &tokens); err != nil {
		return err
	}
	for _, t := range tokens {
		_ = s.mmJSON(ctx, http.MethodPost, "/api/v4/users/tokens/revoke", map[string]string{"token_id": t.ID}, s.cfg.mmToken, nil)
	}
	return nil
}

func (s *server) disableBot(ctx context.Context, userID string) error {
	return s.mmJSON(ctx, http.MethodPost, "/api/v4/bots/"+userID+"/disable", nil, s.cfg.mmToken, nil)
}

func (s *server) ensureTeamChannel(ctx context.Context, userID string) error {
	var team struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := s.mmJSON(ctx, http.MethodGet, "/api/v4/teams/name/"+s.cfg.defaultTeam, nil, s.cfg.mmToken, &team); err != nil {
		return fmt.Errorf("team %q: %w", s.cfg.defaultTeam, err)
	}
	_ = s.mmJSON(ctx, http.MethodPost, "/api/v4/teams/"+team.ID+"/members", map[string]string{
		"team_id": team.ID,
		"user_id": userID,
	}, s.cfg.mmToken, nil)

	var ch struct {
		ID string `json:"id"`
	}
	if err := s.mmJSON(ctx, http.MethodGet, "/api/v4/teams/"+team.ID+"/channels/name/"+s.cfg.defaultChannel, nil, s.cfg.mmToken, &ch); err != nil {
		return fmt.Errorf("channel %q: %w", s.cfg.defaultChannel, err)
	}
	return s.mmJSON(ctx, http.MethodPost, "/api/v4/channels/"+ch.ID+"/members", map[string]string{
		"user_id": userID,
	}, s.cfg.mmToken, nil)
}

type httpError struct {
	status int
	body   string
}

func (e *httpError) Error() string { return fmt.Sprintf("mm api %d: %s", e.status, e.body) }

func isNotFound(err error) bool {
	var he *httpError
	return errors.As(err, &he) && he.status == http.StatusNotFound
}

func (s *server) mmJSON(ctx context.Context, method, path string, body any, token string, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.cfg.mmURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode >= 300 {
		return &httpError{status: res.StatusCode, body: string(data)}
	}
	if out == nil || len(data) == 0 || string(data) == "null" {
		return nil
	}
	return json.Unmarshal(data, out)
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

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		slog.Error("missing env", "key", k)
		os.Exit(1)
	}
	return v
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(k))
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
