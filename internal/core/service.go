package core

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Error kinds; the HTTP layer maps them to status codes.
var (
	ErrBadRequest    = errors.New("bad request")
	ErrUnauthorized  = errors.New("unauthorized")
	ErrForbidden     = errors.New("forbidden")
	ErrConflict      = errors.New("conflict")
	ErrUpstream      = errors.New("provider error")
	ErrNoSuchChannel = errors.New("no such channel")
)

var (
	nameRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$`)
	userRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	channelRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

// ValidName says whether name is a valid agent name (without the prefix).
func ValidName(name string) bool { return nameRE.MatchString(name) }

// Policy is the registrar's configuration as the protocol sees it. Every
// value comes from the environment; nothing here assumes a default name.
type Policy struct {
	BotPrefix        string
	DefaultChannel   string // the channel a bot joins when its scope names none
	SharedSecret     string // "" disables registration with the shared secret
	MaxTrusted       int
	DefaultTTL       time.Duration
	MaxTTL           time.Duration
	DefaultMaxBots   int
	MaxBotsLimit     int
	MaxTokensPerUser int
	// TokenRetention is how long a revoked or expired token stays in the
	// store before it is pruned; 0 prunes it at the next pass.
	TokenRetention time.Duration
}

// Service runs the protocol: registration (shared secret or enrollment
// token), unregistration and the token command.
type Service struct {
	Provider ProviderPort
	Store    *Store // nil: enrollment tokens are off
	Policy   Policy
	Log      *slog.Logger
	Now      func() time.Time

	enrollMu sync.Mutex // serialises enrollments, so MaxBots holds under concurrency
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// RegisterRequest is the body of POST /register/v1/agents.
type RegisterRequest struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Responsible string   `json:"responsible"`
	Trusted     []string `json:"trusted"`
	Kind        string   `json:"kind"`     // "session" (default) or "autonomous"
	Channels    []string `json:"channels"` // optional; enrollment tokens only
}

// Registration is what a successful registration returns.
type Registration struct {
	Agent      Agent
	Credential string
	Owner      string // handle of the bound owner; "" when unbound
}

func (s *Service) isSharedSecret(cred string) bool {
	return s.Policy.SharedSecret != "" && cred != "" &&
		subtle.ConstantTimeCompare([]byte(cred), []byte(s.Policy.SharedSecret)) == 1
}

// enrollment resolves an enrollment token; it refuses unknown, expired and
// revoked ones.
func (s *Service) enrollment(cred string) (Token, error) {
	if s.Store == nil || !strings.HasPrefix(cred, TokenPrefix) {
		return Token{}, ErrUnauthorized
	}
	t, ok := s.Store.Lookup(cred)
	if !ok {
		return Token{}, ErrUnauthorized
	}
	if t.RevokedAt != nil {
		return Token{}, fmt.Errorf("%w: enrollment token %s is revoked", ErrUnauthorized, t.ID)
	}
	if !t.Active(s.now()) {
		return Token{}, fmt.Errorf("%w: enrollment token %s expired", ErrUnauthorized, t.ID)
	}
	return t, nil
}

func normHandle(raw string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(raw), "@"))
}

func normKind(k string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "":
		return "", nil
	case "session":
		return "session", nil
	case "autonomous":
		return "autonomous", nil
	}
	return "", fmt.Errorf("%w: kind must be session or autonomous", ErrBadRequest)
}

func normChannels(raw []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, c := range raw {
		c = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(c), "~"))
		if c == "" || seen[c] {
			continue
		}
		if !channelRE.MatchString(c) {
			return nil, fmt.Errorf("%w: invalid channel name %q", ErrBadRequest, c)
		}
		seen[c] = true
		out = append(out, c)
	}
	return out, nil
}

// Register creates an agent. cred is the Bearer credential: the shared secret
// (an unbound bot) or an enrollment token (a bot bound to the token's owner).
func (s *Service) Register(ctx context.Context, cred string, req RegisterRequest) (Registration, error) {
	shared := s.isSharedSecret(cred)
	var tok Token
	if !shared {
		var err error
		if tok, err = s.enrollment(cred); err != nil {
			return Registration{}, err
		}
		s.enrollMu.Lock()
		defer s.enrollMu.Unlock()
	}

	name := strings.ToLower(strings.TrimSpace(req.Name))
	if !ValidName(name) {
		return Registration{}, fmt.Errorf("%w: invalid name (use 3-32 lowercase alnum/hyphen)", ErrBadRequest)
	}
	username := s.Policy.BotPrefix + name
	display := strings.TrimSpace(req.DisplayName)
	if display == "" {
		display = username
	}
	kind, err := normKind(req.Kind)
	if err != nil {
		return Registration{}, err
	}
	channels, err := normChannels(req.Channels)
	if err != nil {
		return Registration{}, err
	}

	var owner *Human
	if shared {
		// Unbound: the default channel only, as before enrollment tokens.
		channels = []string{s.Policy.DefaultChannel}
	} else {
		if owner, err = s.Provider.HumanByID(ctx, tok.OwnerID); err != nil {
			return Registration{}, fmt.Errorf("%w: owner lookup: %v", ErrUpstream, err)
		}
		if owner == nil {
			return Registration{}, fmt.Errorf("%w: the token's owner is no longer an active user", ErrForbidden)
		}
		if r := normHandle(req.Responsible); r != "" && r != owner.Handle {
			return Registration{}, fmt.Errorf("%w: responsible @%s is not the token's owner @%s; leave it out or name the owner", ErrForbidden, r, owner.Handle)
		}
		if kind == "" {
			kind = tok.Kind
		} else if kind != tok.Kind {
			return Registration{}, fmt.Errorf("%w: the token allows kind %s only", ErrForbidden, tok.Kind)
		}
		if n := s.Store.LiveAgents(tok.ID); n >= tok.MaxBots {
			return Registration{}, fmt.Errorf("%w: the token's %d bots are registered; unregister one first", ErrForbidden, tok.MaxBots)
		}
		allowed := tok.Channels
		if len(allowed) == 0 {
			allowed = []string{s.Policy.DefaultChannel}
		}
		if len(channels) == 0 {
			channels = allowed
		}
		for _, c := range channels {
			if !contains(allowed, c) {
				return Registration{}, fmt.Errorf("%w: the token does not allow channel %s", ErrForbidden, c)
			}
			ok, err := s.Provider.HumanCanAccess(ctx, *owner, c)
			if errors.Is(err, ErrNoSuchChannel) {
				return Registration{}, fmt.Errorf("%w: channel %s does not exist", ErrForbidden, c)
			}
			if err != nil {
				return Registration{}, fmt.Errorf("%w: channel check: %v", ErrUpstream, err)
			}
			if !ok {
				return Registration{}, fmt.Errorf("%w: @%s has no access to channel %s", ErrForbidden, owner.Handle, c)
			}
		}
	}

	if existing, err := s.Provider.FindAgent(ctx, username); err != nil {
		return Registration{}, fmt.Errorf("%w: lookup %s: %v", ErrUpstream, username, err)
	} else if existing != nil {
		return Registration{}, fmt.Errorf("%w: agent already registered", ErrConflict)
	}

	profile := s.describe(ctx, owner, req.Responsible, kind, req.Trusted)
	agent, err := s.Provider.CreateAgent(ctx, username, display, profile)
	if err != nil {
		return Registration{}, fmt.Errorf("%w: create bot: %v", ErrUpstream, err)
	}
	credential, err := s.Provider.IssueCredential(ctx, agent)
	if err != nil {
		s.undo(ctx, agent)
		return Registration{}, fmt.Errorf("%w: create token: %v", ErrUpstream, err)
	}
	if err := s.Provider.JoinChannels(ctx, agent, channels); err != nil {
		s.Log.Warn("team/channel invite", "err", err, "user_id", agent.ID)
	}
	out := Registration{Agent: agent, Credential: credential}
	if owner == nil {
		s.Log.Info("registered unbound agent", "username", username)
		return out, nil
	}
	// Bind last: once the human owns the bot, a registrar token without
	// manage_others_bots could no longer mint its token.
	if err := s.Provider.BindOwner(ctx, agent, *owner); err != nil {
		s.undo(ctx, agent)
		return Registration{}, fmt.Errorf("%w: bind owner: %v", ErrUpstream, err)
	}
	now := s.now()
	if err := s.Store.AddAgent(AgentRecord{UserID: agent.ID, Username: agent.Username, TokenID: tok.ID, OwnerID: owner.ID, CreatedAt: now}); err != nil {
		s.undo(ctx, agent)
		return Registration{}, fmt.Errorf("record agent: %w", err)
	}
	if err := s.Store.Touch(tok.ID, now); err != nil {
		s.Log.Warn("touch token", "err", err, "token_id", tok.ID)
	}
	out.Owner = owner.Handle
	s.Log.Info("registered bound agent", "username", username, "owner", owner.Handle, "token_id", tok.ID)
	return out, nil
}

func (s *Service) undo(ctx context.Context, a Agent) {
	if err := s.Provider.RevokeAgent(ctx, a); err != nil {
		s.Log.Error("undo registration", "err", err, "user_id", a.ID)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// Unregister revokes and disables the agent name. It accepts the shared
// secret (operator cleanup), the agent's own credential, or an active
// enrollment token of the agent's owner. Idempotent: a missing agent is done.
func (s *Service) Unregister(ctx context.Context, cred, name string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if !ValidName(name) {
		return fmt.Errorf("%w: invalid name", ErrBadRequest)
	}
	if cred == "" {
		return ErrUnauthorized
	}
	username := s.Policy.BotPrefix + name
	agent, err := s.Provider.FindAgent(ctx, username)
	if err != nil {
		return fmt.Errorf("%w: lookup: %v", ErrUpstream, err)
	}
	if agent == nil {
		if s.Store != nil {
			_ = s.Store.RemoveAgent(username)
		}
		return nil
	}
	ok := s.isSharedSecret(cred)
	if !ok && strings.HasPrefix(cred, TokenPrefix) {
		// Never send an enrollment token to the provider as a credential.
		tok, err := s.enrollment(cred)
		if err != nil {
			return err
		}
		rec, found := s.Store.Agent(username)
		ok = found && rec.OwnerID == tok.OwnerID
	} else if !ok {
		me, err := s.Provider.AgentForCredential(ctx, cred)
		ok = err == nil && me != nil && me.ID == agent.ID
	}
	if !ok {
		return ErrUnauthorized
	}
	return s.disable(ctx, *agent)
}

// disable revokes the agent through the provider and forgets its record:
// the one way the registrar removes a bot.
func (s *Service) disable(ctx context.Context, agent Agent) error {
	if err := s.Provider.RevokeAgent(ctx, agent); err != nil {
		return fmt.Errorf("%w: disable: %v", ErrUpstream, err)
	}
	if s.Store != nil {
		if err := s.Store.RemoveAgent(agent.Username); err != nil {
			s.Log.Warn("forget agent", "err", err, "username", agent.Username)
		}
	}
	return nil
}

// unregisterEnrolled removes a bot recorded for a token, as Unregister does.
// A bot that is gone, or whose username now belongs to another account, is
// only forgotten; removed says whether a bot was disabled.
func (s *Service) unregisterEnrolled(ctx context.Context, rec AgentRecord) (removed bool, err error) {
	agent, err := s.Provider.FindAgent(ctx, rec.Username)
	if err != nil {
		return false, fmt.Errorf("%w: lookup: %v", ErrUpstream, err)
	}
	if agent == nil || agent.ID != rec.UserID {
		if agent != nil {
			s.Log.Warn("enrolled username now belongs to another account; forgetting the record only",
				"username", rec.Username, "recorded_id", rec.UserID, "found_id", agent.ID)
		}
		return false, s.Store.RemoveAgent(rec.Username)
	}
	if err := s.disable(ctx, *agent); err != nil {
		return false, err
	}
	return true, nil
}

// PruneTokens drops tokens revoked or expired longer than the retention ago
// that have no live bots (see Store.Prune).
func (s *Service) PruneTokens() {
	if s.Store == nil {
		return
	}
	n, err := s.Store.Prune(s.now(), s.Policy.TokenRetention)
	if err != nil {
		s.Log.Error("prune enrollment tokens", "err", err)
		return
	}
	if n > 0 {
		s.Log.Info("pruned enrollment tokens", "count", n)
	}
}
