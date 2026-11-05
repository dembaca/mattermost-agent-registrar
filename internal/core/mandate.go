package core

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Mandate per channel: a trusted human, typing the mandate command in a
// project channel (the target home), says that the coordinator of
// another channel (~home) gives tasks and priorities for the agents in this
// channel. The registrar stores that and publishes it as a signed record; the
// bus trusts the record, never the endpoint that serves it.
const (
	mandateTyp = "mm-agent-mandate+jwt"
	// MandateTTL is the lifetime of a mandate record. Records are signed fresh
	// for each request, so this only bounds how long a copy stays valid.
	MandateTTL = time.Hour
	// MandateMaxDays is how far in the future an until date may lie.
	MandateMaxDays = 30
	// MandateNoteMax is the longest note, in characters.
	MandateNoteMax = 200

	mandateDateLayout = "2006-01-02"
)

// MandateClaims is the payload of a mandate record. Field order is the wire
// order.
type MandateClaims struct {
	ChannelID string `json:"channel_id"` // the channel the command was typed in
	Home      string `json:"home"`       // channel id of the named home, whose coordinator holds the mandate
	SetBy     string `json:"set_by"`     // the setter's handle, lower case, without "@"
	SetByID   string `json:"set_by_id"`  // the setter's provider user id
	SetAtMs   int64  `json:"set_at_ms"`  // when the human set it, unix milliseconds
	Until     string `json:"until"`      // YYYY-MM-DD, "" when none
	Note      string `json:"note"`       // free text, may be empty
	Iat       int64  `json:"iat"`
	Exp       int64  `json:"exp"`
}

// SignMandate stamps iat (now) and exp (now + MandateTTL) on c and returns
// the compact JWS.
func (a *Attestor) SignMandate(c MandateClaims, now time.Time) (string, error) {
	c.Iat = now.Unix()
	c.Exp = now.Add(MandateTTL).Unix()
	return a.SignMandateExact(c)
}

// SignMandateExact signs c as it is.
func (a *Attestor) SignMandateExact(c MandateClaims) (string, error) {
	return a.signJWS(mandateTyp, c)
}

// VerifyMandate checks the signature, header (typ mm-agent-mandate+jwt) and
// expiry (at now) of a mandate record against pub and returns its claims.
func VerifyMandate(token string, pub ed25519.PublicKey, now time.Time) (MandateClaims, error) {
	var c MandateClaims
	if err := verifyJWS(token, mandateTyp, pub, &c); err != nil {
		return c, err
	}
	if now.Unix() >= c.Exp {
		return c, errors.New("expired")
	}
	return c, nil
}

// ChannelMandate is the mandate a human set for one channel.
type ChannelMandate struct {
	ChannelID string    `json:"channel_id"`
	HomeID    string    `json:"home_id"` // channel id of the home
	Home      string    `json:"home"`    // its name as typed, for replies
	SetBy     string    `json:"set_by"`
	SetByID   string    `json:"set_by_id"`
	SetAt     time.Time `json:"set_at"`
	Until     string    `json:"until"` // YYYY-MM-DD or ""
	Note      string    `json:"note"`
}

type mandateState struct {
	Version  int                       `json:"version"`
	Mandates map[string]ChannelMandate `json:"mandates"` // by channel id
}

// MandateStore keeps the mandate per channel in memory and, with a path, in
// its own JSON file, written atomically (temp file + rename, mode 0600) after
// every change. One registrar process owns the file.
type MandateStore struct {
	mu   sync.Mutex
	path string
	st   mandateState
}

// OpenMandateStore loads path, or starts empty when it does not exist. An
// empty path keeps everything in memory (tests).
func OpenMandateStore(path string) (*MandateStore, error) {
	s := &MandateStore{path: path, st: mandateState{Version: 1, Mandates: map[string]ChannelMandate{}}}
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
		return nil, fmt.Errorf("mandate store %s: %w", path, err)
	}
	if s.st.Mandates == nil {
		s.st.Mandates = map[string]ChannelMandate{}
	}
	return s, nil
}

// Get returns the mandate of a channel; ok is false when none is set.
func (s *MandateStore) Get(channelID string) (ChannelMandate, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.st.Mandates[channelID]
	return m, ok
}

// Set stores m as its channel's mandate, replacing any earlier one.
func (s *MandateStore) Set(m ChannelMandate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, had := s.st.Mandates[m.ChannelID]
	s.st.Mandates[m.ChannelID] = m
	if err := s.saveLocked(); err != nil {
		if had {
			s.st.Mandates[m.ChannelID] = old
		} else {
			delete(s.st.Mandates, m.ChannelID)
		}
		return err
	}
	return nil
}

// Delete removes the mandate of a channel (none: no-op).
func (s *MandateStore) Delete(channelID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, had := s.st.Mandates[channelID]
	if !had {
		return nil
	}
	delete(s.st.Mandates, channelID)
	if err := s.saveLocked(); err != nil {
		s.st.Mandates[channelID] = old
		return err
	}
	return nil
}

func (s *MandateStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, ".mandates-*", data)
}

// MandateRecord returns the signed record of a channel's mandate, signed now.
// ErrBadRequest for an invalid channel id, ErrNoMandate when none is set (or
// mandates are off).
func (s *Service) MandateRecord(channelID string) (string, error) {
	if !ValidChannelID(channelID) {
		return "", fmt.Errorf("%w: invalid channel id", ErrBadRequest)
	}
	if s.Mandates == nil || s.Attestor == nil {
		return "", ErrNoMandate
	}
	m, ok := s.Mandates.Get(channelID)
	if !ok {
		return "", ErrNoMandate
	}
	return s.Attestor.SignMandate(MandateClaims{
		ChannelID: m.ChannelID,
		Home:      m.HomeID,
		SetBy:     m.SetBy,
		SetByID:   m.SetByID,
		SetAtMs:   m.SetAt.UnixMilli(),
		Until:     m.Until,
		Note:      m.Note,
	}, s.now())
}

type mandateRequest struct {
	action string // status, off or set
	home   string
	until  string
	note   string
}

// parseMandate parses the text after the trigger. The error is the refusal
// shown to the caller; "" means the usage text.
func parseMandate(text string, today time.Time) (mandateRequest, string) {
	text = strings.TrimSpace(text)
	if strings.EqualFold(text, "status") || text == "" {
		return mandateRequest{action: "status"}, ""
	}
	if strings.EqualFold(text, "off") {
		return mandateRequest{action: "off"}, ""
	}
	if strings.ContainsAny(text, "\r\n") {
		return mandateRequest{}, "The note must be one line."
	}
	next := func() string { // pops the next whitespace-separated word
		i := strings.IndexAny(text, " \t")
		if i < 0 {
			w := text
			text = ""
			return w
		}
		w := text[:i]
		text = strings.TrimSpace(text[i:])
		return w
	}
	if !strings.EqualFold(next(), "set") {
		return mandateRequest{}, ""
	}
	home := strings.ToLower(strings.TrimPrefix(next(), "~"))
	if home == "" || !channelRE.MatchString(home) {
		return mandateRequest{}, ""
	}
	req := mandateRequest{action: "set", home: home}
	if i := strings.IndexAny(text, " \t"); strings.EqualFold(text, "until") || (i > 0 && strings.EqualFold(text[:i], "until")) {
		next()
		d := next()
		if d == "" {
			return mandateRequest{}, "`until` needs a date: YYYY-MM-DD."
		}
		t, err := time.Parse(mandateDateLayout, d)
		if err != nil {
			return mandateRequest{}, "`" + d + "` is not a valid date; use YYYY-MM-DD."
		}
		switch {
		case t.Before(today):
			return mandateRequest{}, "The date " + d + " is in the past; today is " + today.Format(mandateDateLayout) + "."
		case t.After(today.AddDate(0, 0, MandateMaxDays)):
			return mandateRequest{}, fmt.Sprintf("The date %s is more than %d days away; the last allowed date is %s.", d, MandateMaxDays, today.AddDate(0, 0, MandateMaxDays).Format(mandateDateLayout))
		}
		req.until = d
	}
	if utf8.RuneCountInString(text) > MandateNoteMax {
		return mandateRequest{}, fmt.Sprintf("The note is too long (%d characters, at most %d).", utf8.RuneCountInString(text), MandateNoteMax)
	}
	req.note = text
	return req, ""
}

// MandateCommand runs the mandate command for a verified invocation and
// returns the private reply: status, set, off or help.
func (s *Service) MandateCommand(ctx context.Context, inv Invocation) string {
	if s.Mandates == nil || s.Attestor == nil {
		return "Mandates are not enabled on this registrar."
	}
	trigger := inv.Command
	if trigger == "" {
		trigger = "/<command>"
	}
	now := s.now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	req, refusal := parseMandate(inv.Text, today)
	if refusal != "" {
		return refusal + "\n\n" + mandateUsage(trigger)
	}
	if req.action == "" {
		return mandateUsage(trigger)
	}
	if msg := s.checkChannelAccess(ctx, inv,
		"Mandates are set per team channel, not in direct or group messages.",
		"Only members of this channel can see or set its mandate."); msg != "" {
		return msg
	}
	cur, had := s.Mandates.Get(inv.ChannelID)
	switch req.action {
	case "status":
		if !had {
			return "Mandate of this channel: not set."
		}
		return "Mandate of this channel: " + describeMandate(cur) + "."
	case "off":
		if !had {
			return "This channel has no mandate."
		}
		if err := s.Mandates.Delete(inv.ChannelID); err != nil {
			s.Log.Error("remove mandate", "err", err, "channel_id", inv.ChannelID)
			return "Removing the mandate failed; try again."
		}
		s.Log.Info("removed mandate", "by", inv.Human.Handle, "channel_id", inv.ChannelID, "home_id", cur.HomeID)
		return "Mandate removed: the coordinator of ~" + cur.Home + " no longer gives tasks for this channel."
	}
	if inv.TeamID == "" {
		return "This command needs a team; run it in a team channel."
	}
	homeID, err := s.Provider.ChannelIDByName(ctx, inv.TeamID, req.home)
	switch {
	case errors.Is(err, ErrNoSuchChannel):
		// The same answer as for a channel the human is not in: a stranger must
		// not learn that a private channel of this name exists.
		return notMemberOfHome(req.home)
	case err != nil || !ValidChannelID(homeID):
		s.Log.Error("resolve mandate home", "err", err, "home", req.home, "team_id", inv.TeamID)
		return "Resolving ~" + req.home + " failed; try again."
	}
	// The home's id goes into a public record: only a channel the human is a
	// member of can be named, so a private channel's id is not handed out.
	if in, err := s.Provider.HumanInChannel(ctx, inv.Human, homeID); err != nil {
		s.Log.Error("home membership check", "err", err, "home", req.home, "channel_id", homeID)
		return "Checking ~" + req.home + " failed; try again."
	} else if !in {
		return notMemberOfHome(req.home)
	}
	m := ChannelMandate{ChannelID: inv.ChannelID, HomeID: homeID, Home: req.home, SetBy: inv.Human.Handle,
		SetByID: inv.Human.ID, SetAt: s.now(), Until: req.until, Note: req.note}
	if err := s.Mandates.Set(m); err != nil {
		s.Log.Error("set mandate", "err", err, "channel_id", inv.ChannelID)
		return "Setting the mandate failed; try again."
	}
	s.Log.Info("set mandate", "by", inv.Human.Handle, "channel_id", inv.ChannelID, "home_id", homeID, "until", req.until)
	out := "Mandate set: the coordinator of ~" + req.home + " gives tasks and priorities for the agents in this channel"
	if req.until != "" {
		out += ", until " + req.until
	} else {
		out += ", with no end date (the bus applies its own default)"
	}
	if had {
		out += " (replaces: " + describeMandate(cur) + ")"
	}
	return out + ". Agents here pick it up the next time they fetch it."
}

func notMemberOfHome(home string) string {
	return "~" + home + " is not a channel you are a member of (or it does not exist); a mandate can only name a channel you are in."
}

func describeMandate(m ChannelMandate) string {
	out := fmt.Sprintf("the coordinator of ~%s gives tasks and priorities here, set by @%s on %s", m.Home, m.SetBy, fmtModeTime(m.SetAt))
	if m.Until != "" {
		out += ", until " + m.Until
	} else {
		out += ", no end date (the bus applies its own default)"
	}
	if m.Note != "" {
		out += ". Note: " + m.Note
	}
	return out
}

func mandateUsage(trigger string) string {
	return "A mandate says that the coordinator of another channel gives tasks and priorities for the agents in this channel.\n\n" +
		"- `" + trigger + " set ~<home> [until YYYY-MM-DD] [note]`: set it (`until` at most 30 days ahead; note up to 200 characters, one line)\n" +
		"- `" + trigger + " off`: remove the mandate of this channel\n" +
		"- `" + trigger + "` or `" + trigger + " status`: show it\n\n" +
		"The mandate and its note are published in a record that anyone can read without logging in: put nothing confidential in the note."
}
