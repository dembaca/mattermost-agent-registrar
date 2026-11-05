package core

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Ask mode per channel (ADR-005 of the agent bus): a human sets with the mode
// command how the agents in a team channel route their questions, and the
// registrar publishes it as a signed record. The bus trusts the record, never
// the endpoint that serves it.
const (
	modeTyp = "mm-agent-mode+jwt"
	// ModeDirect: agents ask humans directly.
	ModeDirect = "direct"
	// ModeCoordinator: agents ask the coordinator first; approvals still go
	// to a human.
	ModeCoordinator = "coordinator"
	// ModeTTL is the lifetime of a mode record. Records are signed fresh for
	// each request, so this only bounds how long a copy stays valid.
	ModeTTL = time.Hour
)

var channelIDRE = regexp.MustCompile(`^[a-z0-9]{26}$`)

// ValidChannelID says whether id looks like a provider channel id (26
// lowercase alphanumerics, as Mattermost ids are).
func ValidChannelID(id string) bool { return channelIDRE.MatchString(id) }

// ModeClaims is the payload of a mode record. Field order is the wire order.
type ModeClaims struct {
	ChannelID string `json:"channel_id"`
	Mode      string `json:"mode"`
	SetBy     string `json:"set_by"`    // the setter's handle, lower case, without "@"
	SetByID   string `json:"set_by_id"` // the setter's provider user id
	SetAtMs   int64  `json:"set_at_ms"` // when the human set it, unix milliseconds
	Iat       int64  `json:"iat"`
	Exp       int64  `json:"exp"`
}

// SignMode stamps iat (now) and exp (now + ModeTTL) on c and returns the
// compact JWS.
func (a *Attestor) SignMode(c ModeClaims, now time.Time) (string, error) {
	c.Iat = now.Unix()
	c.Exp = now.Add(ModeTTL).Unix()
	return a.SignModeExact(c)
}

// SignModeExact signs c as it is.
func (a *Attestor) SignModeExact(c ModeClaims) (string, error) {
	return a.signJWS(modeTyp, c)
}

// VerifyMode checks the signature, header (typ mm-agent-mode+jwt) and expiry
// (at now) of a mode record against pub and returns its claims.
func VerifyMode(token string, pub ed25519.PublicKey, now time.Time) (ModeClaims, error) {
	var c ModeClaims
	if err := verifyJWS(token, modeTyp, pub, &c); err != nil {
		return c, err
	}
	if now.Unix() >= c.Exp {
		return c, errors.New("expired")
	}
	return c, nil
}

// ChannelMode is the ask mode a human set for one channel.
type ChannelMode struct {
	ChannelID string    `json:"channel_id"`
	Mode      string    `json:"mode"`
	SetBy     string    `json:"set_by"`
	SetByID   string    `json:"set_by_id"`
	SetAt     time.Time `json:"set_at"`
}

type modeState struct {
	Version int                    `json:"version"`
	Modes   map[string]ChannelMode `json:"modes"` // by channel id
}

// ModeStore keeps the current mode per channel in memory and, with a path, in
// its own JSON file, written atomically (temp file + rename, mode 0600) after
// every change. It is separate from the enrollment store, so modes work
// without enrollment tokens. One registrar process owns the file.
type ModeStore struct {
	mu   sync.Mutex
	path string
	st   modeState
}

// OpenModeStore loads path, or starts empty when it does not exist. An empty
// path keeps everything in memory (tests).
func OpenModeStore(path string) (*ModeStore, error) {
	s := &ModeStore{path: path, st: modeState{Version: 1, Modes: map[string]ChannelMode{}}}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &s.st); err != nil {
		return nil, fmt.Errorf("mode store %s: %w", path, err)
	}
	if s.st.Modes == nil {
		s.st.Modes = map[string]ChannelMode{}
	}
	return s, nil
}

// Get returns the mode of a channel; ok is false when none is set.
func (s *ModeStore) Get(channelID string) (ChannelMode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.st.Modes[channelID]
	return m, ok
}

// Set stores m as its channel's mode, replacing any earlier one (also the
// same mode: who set it and when are updated).
func (s *ModeStore) Set(m ChannelMode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, had := s.st.Modes[m.ChannelID]
	s.st.Modes[m.ChannelID] = m
	if err := s.saveLocked(); err != nil {
		if had {
			s.st.Modes[m.ChannelID] = old
		} else {
			delete(s.st.Modes, m.ChannelID)
		}
		return err
	}
	return nil
}

func (s *ModeStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, ".modes-*", data)
}

// ModeRecord returns the signed record of a channel's mode, signed now.
// ErrBadRequest for an invalid channel id, ErrNoMode when none is set (or
// modes are off).
func (s *Service) ModeRecord(channelID string) (string, error) {
	if !ValidChannelID(channelID) {
		return "", fmt.Errorf("%w: invalid channel id", ErrBadRequest)
	}
	if s.Modes == nil || s.Attestor == nil {
		return "", ErrNoMode
	}
	m, ok := s.Modes.Get(channelID)
	if !ok {
		return "", ErrNoMode
	}
	return s.Attestor.SignMode(ModeClaims{
		ChannelID: m.ChannelID,
		Mode:      m.Mode,
		SetBy:     m.SetBy,
		SetByID:   m.SetByID,
		SetAtMs:   m.SetAt.UnixMilli(),
	}, s.now())
}

// ModeCommand runs the mode command for a verified invocation and returns the
// private reply: status, direct, coordinator, delegated or help.
func (s *Service) ModeCommand(ctx context.Context, inv Invocation) string {
	if s.Modes == nil || s.Attestor == nil {
		return "Ask modes are not enabled on this registrar."
	}
	trigger := inv.Command
	if trigger == "" {
		trigger = "/<command>"
	}
	args, err := splitArgs(inv.Text)
	if err != nil || len(args) > 1 {
		return modeUsage(trigger)
	}
	arg := "status"
	if len(args) == 1 {
		arg = strings.ToLower(args[0])
	}
	switch arg {
	case "status", ModeDirect, ModeCoordinator:
	case "delegated":
		return "`delegated` is not available yet (ADR-005 phase 3)."
	default:
		return modeUsage(trigger)
	}
	if msg := s.checkModeChannel(ctx, inv); msg != "" {
		return msg
	}
	cur, had := s.Modes.Get(inv.ChannelID)
	if arg == "status" {
		if !had {
			return "Ask mode of this channel: not set (agents use their default, `direct` unless configured otherwise)."
		}
		return fmt.Sprintf("Ask mode of this channel: `%s`, set by @%s on %s.", cur.Mode, cur.SetBy, fmtModeTime(cur.SetAt))
	}
	m := ChannelMode{ChannelID: inv.ChannelID, Mode: arg, SetBy: inv.Human.Handle, SetByID: inv.Human.ID, SetAt: s.now()}
	if err := s.Modes.Set(m); err != nil {
		s.Log.Error("set ask mode", "err", err, "channel_id", inv.ChannelID)
		return "Setting the mode failed; try again."
	}
	s.Log.Info("set ask mode", "by", inv.Human.Handle, "channel_id", inv.ChannelID, "mode", arg)
	out := "Ask mode of this channel is now `" + arg + "`"
	if had {
		out += fmt.Sprintf(" (was `%s`, set by @%s on %s)", cur.Mode, cur.SetBy, fmtModeTime(cur.SetAt))
	}
	return out + ". Agents in this channel pick it up the next time they fetch it."
}

// checkModeChannel returns why the invocation's channel cannot have a mode
// (not a team channel, missing, caller not a member), or "".
func (s *Service) checkModeChannel(ctx context.Context, inv Invocation) string {
	return s.checkChannelAccess(ctx, inv, "Ask modes are set per team channel, not in direct or group messages.",
		"Only members of this channel can see or set its ask mode.")
}

// checkChannelAccess is the check behind the channel commands: the
// invocation's channel must be a team channel the caller is a member of.
// noTeam and notMember are the refusals for a direct or group message and for
// a non-member.
func (s *Service) checkChannelAccess(ctx context.Context, inv Invocation, noTeam, notMember string) string {
	if !ValidChannelID(inv.ChannelID) {
		return "This command needs a channel; run it in a team channel."
	}
	ok, err := s.Provider.HumanInChannel(ctx, inv.Human, inv.ChannelID)
	switch {
	case errors.Is(err, ErrNotTeamChannel):
		return noTeam
	case errors.Is(err, ErrNoSuchChannel):
		return "This channel was not found."
	case err != nil:
		s.Log.Error("channel membership check", "err", err, "channel_id", inv.ChannelID)
		return "Checking the channel failed; try again."
	case !ok:
		return notMember
	}
	return ""
}

func fmtModeTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

func modeUsage(trigger string) string {
	return "The ask mode of a channel says how the agents in it route their questions.\n\n" +
		"- `" + trigger + "` or `" + trigger + " status`: the mode of this channel\n" +
		"- `" + trigger + " direct`: agents ask humans directly\n" +
		"- `" + trigger + " coordinator`: agents ask the coordinator first; approvals still go to a human\n" +
		"- `" + trigger + " delegated`: not available yet (ADR-005 phase 3)"
}
