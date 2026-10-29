// Package mattermost is the registrar's Mattermost adapter: it implements
// core.ProviderPort with the Mattermost REST API v4 and the admin token.
package mattermost

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/dembaca/mattermost-agent-registrar/internal/core"
)

// Config is the adapter's part of the registrar configuration.
type Config struct {
	URL              string   // where the registrar reaches Mattermost
	Token            string   // admin personal access token
	Team             string   // team bots join; channels are names in it
	HideBotDM        bool     // hide the admin↔bot welcome DM
	CommandTokens    []string // verification tokens of the slash command(s)
	TokenDescription string   // description of the bot access tokens it mints
}

// Adapter implements core.ProviderPort for Mattermost.
type Adapter struct {
	Cfg    Config
	Client *http.Client
	Log    *slog.Logger
}

var _ core.ProviderPort = (*Adapter)(nil)

// User is the part of a Mattermost user the registrar reads.
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	IsBot    bool   `json:"is_bot"`
	DeleteAt int64  `json:"delete_at"`
	Roles    string `json:"roles"`
}

// Bot is a Mattermost bot as POST /api/v4/bots returns it.
type Bot struct {
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

// AccessToken is a user access token.
type AccessToken struct {
	Token string `json:"token"`
	ID    string `json:"id"`
}

// Preference is a Mattermost user preference.
type Preference struct {
	UserID   string `json:"user_id"`
	Category string `json:"category"`
	Name     string `json:"name"`
	Value    string `json:"value"`
}

func (u *User) human() bool {
	return u != nil && !u.IsBot && u.DeleteAt == 0
}

func (u *User) guest() bool {
	for _, r := range strings.Fields(u.Roles) {
		if r == "system_guest" {
			return true
		}
	}
	return false
}

// VerifyInvocation checks the slash command's verification token and that
// the caller (Mattermost's user_id) is an active, non-guest human. A bot can
// execute slash commands through the API, so this check matters.
func (m *Adapter) VerifyInvocation(r *http.Request) (core.Invocation, error) {
	if err := r.ParseForm(); err != nil {
		return core.Invocation{}, fmt.Errorf("%w: form: %v", core.ErrBadRequest, err)
	}
	tok := r.PostForm.Get("token")
	if tok == "" {
		// Mattermost sends the token as "Authorization: Token <token>" as well.
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Token ") {
			tok = strings.TrimSpace(h[len("Token "):])
		}
	}
	ok := false
	for _, want := range m.Cfg.CommandTokens {
		if want != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(want)) == 1 {
			ok = true
		}
	}
	if !ok {
		return core.Invocation{}, core.ErrUnauthorized
	}
	uid := r.PostForm.Get("user_id")
	if uid == "" {
		return core.Invocation{}, fmt.Errorf("%w: no user_id", core.ErrBadRequest)
	}
	u, err := m.user(r.Context(), "/api/v4/users/"+url.PathEscape(uid))
	if err != nil {
		return core.Invocation{}, fmt.Errorf("%w: user: %v", core.ErrUpstream, err)
	}
	if !u.human() || u.guest() {
		return core.Invocation{}, fmt.Errorf("%w: only active members (no bots, no guests) can create enrollment tokens", core.ErrForbidden)
	}
	return core.Invocation{
		Human:   core.Human{ID: u.ID, Handle: strings.ToLower(u.Username)},
		Command: r.PostForm.Get("command"),
		Text:    r.PostForm.Get("text"),
	}, nil
}

// ReplyPrivate answers the slash command ephemerally: only the caller sees it.
func (m *Adapter) ReplyPrivate(w http.ResponseWriter, _ core.Invocation, text string) {
	WriteEphemeral(w, text)
}

// WriteEphemeral writes an ephemeral slash command response.
func WriteEphemeral(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"response_type": "ephemeral", "text": text})
}

func (m *Adapter) user(ctx context.Context, path string) (*User, error) {
	var u User
	if err := m.do(ctx, http.MethodGet, path, nil, m.Cfg.Token, &u); err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func asHuman(u *User) *core.Human {
	if !u.human() {
		return nil
	}
	return &core.Human{ID: u.ID, Handle: strings.ToLower(u.Username)}
}

// ResolveHuman finds an active human by username.
func (m *Adapter) ResolveHuman(ctx context.Context, handle string) (*core.Human, error) {
	u, err := m.user(ctx, "/api/v4/users/username/"+url.PathEscape(handle))
	if err != nil {
		return nil, err
	}
	return asHuman(u), nil
}

// HumanByID finds an active human by user id.
func (m *Adapter) HumanByID(ctx context.Context, id string) (*core.Human, error) {
	u, err := m.user(ctx, "/api/v4/users/"+url.PathEscape(id))
	if err != nil {
		return nil, err
	}
	return asHuman(u), nil
}

type team struct {
	ID string `json:"id"`
}

type channel struct {
	ID   string `json:"id"`
	Type string `json:"type"` // O public, P private
}

type member struct {
	DeleteAt int64 `json:"delete_at"`
}

func (m *Adapter) team(ctx context.Context) (team, error) {
	var t team
	err := m.do(ctx, http.MethodGet, "/api/v4/teams/name/"+url.PathEscape(m.Cfg.Team), nil, m.Cfg.Token, &t)
	if err != nil {
		return t, fmt.Errorf("team %q: %w", m.Cfg.Team, err)
	}
	return t, nil
}

// HumanCanAccess: member of the channel, or member of the team and the
// channel is public.
func (m *Adapter) HumanCanAccess(ctx context.Context, h core.Human, name string) (bool, error) {
	t, err := m.team(ctx)
	if err != nil {
		return false, err
	}
	var ch channel
	if err := m.do(ctx, http.MethodGet, "/api/v4/teams/"+t.ID+"/channels/name/"+url.PathEscape(name), nil, m.Cfg.Token, &ch); err != nil {
		if isNotFound(err) {
			return false, core.ErrNoSuchChannel
		}
		return false, err
	}
	var tm member
	if err := m.do(ctx, http.MethodGet, "/api/v4/teams/"+t.ID+"/members/"+url.PathEscape(h.ID), nil, m.Cfg.Token, &tm); err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, err
	}
	if tm.DeleteAt != 0 {
		return false, nil // left the team
	}
	err = m.do(ctx, http.MethodGet, "/api/v4/channels/"+ch.ID+"/members/"+url.PathEscape(h.ID), nil, m.Cfg.Token, nil)
	if err == nil {
		return true, nil
	}
	if !isNotFound(err) {
		return false, err
	}
	return ch.Type == "O", nil
}

// FindAgent finds an account by username.
func (m *Adapter) FindAgent(ctx context.Context, username string) (*core.Agent, error) {
	u, err := m.user(ctx, "/api/v4/users/username/"+url.PathEscape(username))
	if err != nil || u == nil {
		return nil, err
	}
	return &core.Agent{ID: u.ID, Username: u.Username}, nil
}

// AgentForCredential returns the account a bot token belongs to.
func (m *Adapter) AgentForCredential(ctx context.Context, credential string) (*core.Agent, error) {
	var u User
	if err := m.do(ctx, http.MethodGet, "/api/v4/users/me", nil, credential, &u); err != nil {
		return nil, err
	}
	return &core.Agent{ID: u.ID, Username: u.Username}, nil
}

// CreateAgent creates the bot; its owner is the admin token's user until
// BindOwner moves it.
func (m *Adapter) CreateAgent(ctx context.Context, username, display, profile string) (core.Agent, error) {
	body := map[string]any{"username": username, "display_name": display, "description": profile}
	var bot Bot
	if err := m.do(ctx, http.MethodPost, "/api/v4/bots", body, m.Cfg.Token, &bot); err != nil {
		return core.Agent{}, err
	}
	if m.Cfg.HideBotDM {
		// Cosmetic: never fail registration if this fails.
		m.HideBotDirectChannel(ctx, bot.UserID)
	}
	return core.Agent{ID: bot.UserID, Username: bot.Username}, nil
}

// BindOwner makes the human the bot's native owner (assign_bot). Mattermost
// then disables the bot when the owner is deactivated
// (DisableBotsWhenOwnerIsDeactivated).
func (m *Adapter) BindOwner(ctx context.Context, a core.Agent, owner core.Human) error {
	return m.do(ctx, http.MethodPost, "/api/v4/bots/"+url.PathEscape(a.ID)+"/assign/"+url.PathEscape(owner.ID), nil, m.Cfg.Token, nil)
}

// IssueCredential mints the bot's access token.
func (m *Adapter) IssueCredential(ctx context.Context, a core.Agent) (string, error) {
	var tok AccessToken
	err := m.do(ctx, http.MethodPost, "/api/v4/users/"+url.PathEscape(a.ID)+"/tokens",
		map[string]string{"description": m.Cfg.TokenDescription}, m.Cfg.Token, &tok)
	if err != nil {
		return "", err
	}
	if tok.Token == "" {
		return "", errors.New("empty token")
	}
	return tok.Token, nil
}

// JoinChannels adds the bot to the team and to each channel.
func (m *Adapter) JoinChannels(ctx context.Context, a core.Agent, channels []string) error {
	t, err := m.team(ctx)
	if err != nil {
		return err
	}
	_ = m.do(ctx, http.MethodPost, "/api/v4/teams/"+t.ID+"/members", map[string]string{
		"team_id": t.ID,
		"user_id": a.ID,
	}, m.Cfg.Token, nil)
	var errs []error
	for _, name := range channels {
		var ch channel
		if err := m.do(ctx, http.MethodGet, "/api/v4/teams/"+t.ID+"/channels/name/"+url.PathEscape(name), nil, m.Cfg.Token, &ch); err != nil {
			errs = append(errs, fmt.Errorf("channel %q: %w", name, err))
			continue
		}
		if err := m.do(ctx, http.MethodPost, "/api/v4/channels/"+ch.ID+"/members", map[string]string{"user_id": a.ID}, m.Cfg.Token, nil); err != nil {
			errs = append(errs, fmt.Errorf("join %q: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// RevokeAgent revokes the bot's access tokens and disables it.
func (m *Adapter) RevokeAgent(ctx context.Context, a core.Agent) error {
	var tokens []AccessToken
	if err := m.do(ctx, http.MethodGet, "/api/v4/users/"+url.PathEscape(a.ID)+"/tokens?per_page=200", nil, m.Cfg.Token, &tokens); err == nil {
		for _, t := range tokens {
			_ = m.do(ctx, http.MethodPost, "/api/v4/users/tokens/revoke", map[string]string{"token_id": t.ID}, m.Cfg.Token, nil)
		}
	}
	return m.do(ctx, http.MethodPost, "/api/v4/bots/"+url.PathEscape(a.ID)+"/disable", nil, m.Cfg.Token, nil)
}

// HideBotDirectChannel hides the admin↔bot DM from the registrar account's sidebar.
//
// Mattermost CreateBot synchronously opens a DM with the creating user and posts the
// "add me to teams/channels" welcome message before returning the bot. That path also
// sets direct_channel_show=true for the creator. Setting the preference here (after
// createBot returns) therefore runs after that write — no delay is required. If a
// future Mattermost version posts the welcome async and the sidebar entry reappears,
// re-set the preference after the DM channel exists or after a short settle delay.
func (m *Adapter) HideBotDirectChannel(ctx context.Context, botUserID string) {
	var me User
	if err := m.do(ctx, http.MethodGet, "/api/v4/users/me", nil, m.Cfg.Token, &me); err != nil || me.ID == "" {
		m.Log.Warn("hide bot dm: get me", "err", err, "bot_user_id", botUserID)
		return
	}
	prefs := []Preference{{UserID: me.ID, Category: "direct_channel_show", Name: botUserID, Value: "false"}}
	if err := m.do(ctx, http.MethodPut, "/api/v4/users/me/preferences", prefs, m.Cfg.Token, nil); err != nil {
		m.Log.Warn("hide bot dm", "err", err, "bot_user_id", botUserID, "admin_user_id", me.ID)
	}
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

func (m *Adapter) do(ctx context.Context, method, path string, body any, token string, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, m.Cfg.URL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := m.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode >= 300 {
		return &httpError{status: res.StatusCode, body: string(data)}
	}
	if out == nil || len(data) == 0 || string(data) == "null" {
		return nil
	}
	return json.Unmarshal(data, out)
}
