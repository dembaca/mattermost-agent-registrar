package core

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// MCP debug per home (ADR-010 phase 1 of the agent bus): a human switches with
// the debug command which categories of its own decisions each agent's MCP
// server shows in the home, and until when. The registrar keeps one setting
// per channel, builds each new one from the previous one's categories and the
// command, and publishes it as a signed record. The bus trusts the record,
// never the endpoint that serves it, and counts it only when set_by_id is one
// of its own trusted humans.
const (
	debugTyp = "mm-agent-debug+jwt"
	// DebugTTL is the lifetime of a debug record's signature. Records are
	// signed fresh for each request, so this only bounds how long a copy stays
	// valid; the setting's own end is until_ms.
	DebugTTL = time.Hour
	// DebugDefault is how long a setting lasts without "for <duration>".
	DebugDefault = time.Hour
	// DebugMax is the longest "for <duration>".
	DebugMax = 24 * time.Hour
	// DebugMin is the shortest "for <duration>".
	DebugMin = time.Minute
)

// DebugCategories are the debug categories in their canonical (wire) order.
// "full" is a command word for all of them, never a category of a record.
var DebugCategories = []string{"wake", "identity", "sig", "asks", "calls", "props"}

const debugFull = "full"

// DebugClaims is the payload of a debug record. Field order is the wire order.
type DebugClaims struct {
	ChannelID  string   `json:"channel_id"`
	Categories []string `json:"categories"` // never empty, canonical order, no "full"
	SetBy      string   `json:"set_by"`     // handle of whoever gave the last command, lower case, without "@"
	SetByID    string   `json:"set_by_id"`  // their provider user id
	SetAtMs    int64    `json:"set_at_ms"`  // when the last command was given, unix milliseconds
	UntilMs    int64    `json:"until_ms"`   // when the setting ends, unix milliseconds
	Iat        int64    `json:"iat"`
	Exp        int64    `json:"exp"`
}

// SignDebug stamps iat (now) and exp (now + DebugTTL) on c and returns the
// compact JWS. exp is the signature's freshness, not the setting's end.
func (a *Attestor) SignDebug(c DebugClaims, now time.Time) (string, error) {
	c.Iat = now.Unix()
	c.Exp = now.Add(DebugTTL).Unix()
	return a.SignDebugExact(c)
}

// SignDebugExact signs c as it is.
func (a *Attestor) SignDebugExact(c DebugClaims) (string, error) {
	return a.signJWS(debugTyp, c)
}

// VerifyDebug checks the signature, header (typ mm-agent-debug+jwt) and
// expiry (at now) of a debug record against pub and returns its claims. It
// does not check until_ms: whether the setting still holds is the reader's.
func VerifyDebug(token string, pub ed25519.PublicKey, now time.Time) (DebugClaims, error) {
	var c DebugClaims
	if err := verifyJWS(token, debugTyp, pub, &c); err != nil {
		return c, err
	}
	if now.Unix() >= c.Exp {
		return c, errors.New("expired")
	}
	return c, nil
}

// ChannelDebug is the debug setting of one channel.
type ChannelDebug struct {
	ChannelID  string    `json:"channel_id"`
	Categories []string  `json:"categories"`
	SetBy      string    `json:"set_by"`
	SetByID    string    `json:"set_by_id"`
	SetAt      time.Time `json:"set_at"`
	Until      time.Time `json:"until"`
}

// Active says whether the setting still holds at now.
func (d ChannelDebug) Active(now time.Time) bool { return now.Before(d.Until) && len(d.Categories) > 0 }

type debugState struct {
	Version int                     `json:"version"`
	Debug   map[string]ChannelDebug `json:"debug"` // by channel id
}

// DebugStore keeps the debug setting per channel in memory and, with a path,
// in its own JSON file, written atomically (temp file + rename, mode 0600)
// after every change. One registrar process owns the file.
type DebugStore struct {
	mu   sync.Mutex
	path string
	st   debugState
}

// OpenDebugStore loads path, or starts empty when it does not exist. An empty
// path keeps everything in memory (tests).
func OpenDebugStore(path string) (*DebugStore, error) {
	s := &DebugStore{path: path, st: debugState{Version: 1, Debug: map[string]ChannelDebug{}}}
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
		return nil, fmt.Errorf("debug store %s: %w", path, err)
	}
	if s.st.Debug == nil {
		s.st.Debug = map[string]ChannelDebug{}
	}
	return s, nil
}

// Get returns the stored setting of a channel, ended or not; ok is false when
// none is stored.
func (s *DebugStore) Get(channelID string) (ChannelDebug, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.st.Debug[channelID]
	return d, ok
}

// Set stores d as its channel's setting, replacing any earlier one.
func (s *DebugStore) Set(d ChannelDebug) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, had := s.st.Debug[d.ChannelID]
	s.st.Debug[d.ChannelID] = d
	if err := s.saveLocked(); err != nil {
		if had {
			s.st.Debug[d.ChannelID] = old
		} else {
			delete(s.st.Debug, d.ChannelID)
		}
		return err
	}
	return nil
}

// Delete removes the setting of a channel (none: no-op).
func (s *DebugStore) Delete(channelID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, had := s.st.Debug[channelID]
	if !had {
		return nil
	}
	delete(s.st.Debug, channelID)
	if err := s.saveLocked(); err != nil {
		s.st.Debug[channelID] = old
		return err
	}
	return nil
}

// Prune removes every setting that has ended at now and returns how many.
func (s *DebugStore) Prune(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var gone []ChannelDebug
	for id, d := range s.st.Debug {
		if !d.Active(now) {
			gone = append(gone, d)
			delete(s.st.Debug, id)
		}
	}
	if len(gone) == 0 {
		return 0, nil
	}
	if err := s.saveLocked(); err != nil {
		for _, d := range gone {
			s.st.Debug[d.ChannelID] = d
		}
		return 0, err
	}
	return len(gone), nil
}

func (s *DebugStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, ".debug-*", data)
}

// PruneDebug drops the ended debug settings (at start, then with the token
// pruning). An ended setting is already unpublished; this only frees the store.
func (s *Service) PruneDebug() {
	if s.Debug == nil {
		return
	}
	n, err := s.Debug.Prune(s.now())
	if err != nil {
		s.Log.Error("prune debug settings", "err", err)
		return
	}
	if n > 0 {
		s.Log.Info("pruned ended debug settings", "count", n)
	}
}

// DebugRecord returns the signed record of a channel's debug setting, signed
// now. ErrBadRequest for an invalid channel id, ErrNoDebug when none is set,
// it has ended, or debug is off on this registrar.
func (s *Service) DebugRecord(channelID string) (string, error) {
	if !ValidChannelID(channelID) {
		return "", fmt.Errorf("%w: invalid channel id", ErrBadRequest)
	}
	if s.Debug == nil || s.Attestor == nil {
		return "", ErrNoDebug
	}
	now := s.now()
	d, ok := s.Debug.Get(channelID)
	if !ok || !d.Active(now) {
		return "", ErrNoDebug
	}
	return s.Attestor.SignDebug(DebugClaims{
		ChannelID:  d.ChannelID,
		Categories: slices.Clone(d.Categories),
		SetBy:      d.SetBy,
		SetByID:    d.SetByID,
		SetAtMs:    d.SetAt.UnixMilli(),
		UntilMs:    d.Until.UnixMilli(),
	}, now)
}

type debugRequest struct {
	action     string   // status, on, off, set or full; "" means the usage text
	categories []string // as given, "full" expanded, canonical order
	dur        time.Duration
}

// parseDebug parses the text after the trigger. The second result is the
// refusal shown to the caller; "" with an empty action means the usage text.
func parseDebug(text string) (debugRequest, string) {
	words := strings.Fields(strings.ToLower(text))
	if len(words) == 0 {
		return debugRequest{action: "status"}, ""
	}
	req := debugRequest{action: words[0], dur: DebugDefault}
	rest := words[1:]
	hasFor := false
	if i := slices.Index(rest, "for"); i >= 0 {
		if i != len(rest)-2 {
			return debugRequest{}, "`for` comes last and takes one duration, e.g. `for 2h`."
		}
		d, err := parseTTL(rest[i+1])
		if err != nil {
			return debugRequest{}, "`" + rest[i+1] + "` is not a duration; use e.g. `30m`, `2h` or `1h30m`."
		}
		if d < DebugMin || d > DebugMax {
			return debugRequest{}, fmt.Sprintf("`for %s` is out of range: at least %s, at most %s.", rest[i+1], fmtDur(DebugMin), fmtDur(DebugMax))
		}
		req.dur, hasFor, rest = d, true, rest[:i]
	}
	switch req.action {
	case "status":
		if len(rest) > 0 || hasFor {
			return debugRequest{}, ""
		}
		return req, ""
	case debugFull:
		if len(rest) > 0 {
			return debugRequest{}, "`full` takes no categories; it turns all of them on."
		}
		req.categories = slices.Clone(DebugCategories)
		return req, ""
	case "on", "set", "off":
	default:
		return debugRequest{}, ""
	}
	if len(rest) == 0 {
		switch req.action {
		case "off":
			if hasFor {
				return debugRequest{}, "`off` alone turns everything off; `for` does not apply."
			}
			return req, ""
		default:
			return debugRequest{}, "`" + req.action + "` needs at least one category: " + knownCategories() + "."
		}
	}
	var unknown []string
	given := map[string]bool{}
	for _, w := range rest {
		switch {
		case w == debugFull:
			for _, c := range DebugCategories {
				given[c] = true
			}
		case slices.Contains(DebugCategories, w):
			given[w] = true
		default:
			unknown = append(unknown, "`"+w+"`")
		}
	}
	if len(unknown) > 0 {
		return debugRequest{}, "Unknown debug categor" + plural(len(unknown), "y", "ies") + ": " + strings.Join(unknown, ", ") +
			". Known: " + knownCategories() + "."
	}
	req.categories = canonical(given)
	return req, ""
}

// apply returns the categories after the command, given those in force.
func (r debugRequest) apply(prev []string) []string {
	set := map[string]bool{}
	switch r.action {
	case "on":
		for _, c := range prev {
			set[c] = true
		}
		for _, c := range r.categories {
			set[c] = true
		}
	case "set", debugFull:
		for _, c := range r.categories {
			set[c] = true
		}
	case "off":
		if len(r.categories) > 0 {
			for _, c := range prev {
				set[c] = true
			}
			for _, c := range r.categories {
				delete(set, c)
			}
		}
	}
	return canonical(set)
}

// canonical returns the categories in set in DebugCategories order.
func canonical(set map[string]bool) []string {
	out := []string{}
	for _, c := range DebugCategories {
		if set[c] {
			out = append(out, c)
		}
	}
	return out
}

// DebugCommand runs the debug command for a verified invocation and returns
// the private reply: status, on, off, set, full or help.
func (s *Service) DebugCommand(ctx context.Context, inv Invocation) string {
	if s.Debug == nil || s.Attestor == nil {
		return "Debug is not enabled on this registrar."
	}
	trigger := inv.Command
	if trigger == "" {
		trigger = "/<command>"
	}
	req, refusal := parseDebug(inv.Text)
	if refusal != "" {
		return refusal + "\n\n" + debugUsage(trigger)
	}
	if req.action == "" {
		return debugUsage(trigger)
	}
	if msg := s.checkChannelAccess(ctx, inv,
		"Debug is switched per team channel, not in direct or group messages.",
		"Only members of this channel can see or switch its debug setting."); msg != "" {
		return msg
	}
	now := s.now()
	cur, had := s.Debug.Get(inv.ChannelID)
	active := had && cur.Active(now)
	if req.action == "status" {
		if !active {
			return "Debug in this channel: off."
		}
		return "Debug in this channel: " + describeDebug(cur, now) + "."
	}
	var prev []string
	if active {
		prev = cur.Categories
	}
	next := req.apply(prev)
	if len(next) == 0 {
		if !had {
			return "Debug in this channel: off (it was not on)."
		}
		// An ended setting is removed as well; it was off already.
		if err := s.Debug.Delete(inv.ChannelID); err != nil {
			s.Log.Error("debug off", "err", err, "channel_id", inv.ChannelID)
			return "Switching debug off failed; try again."
		}
		s.Log.Info("debug off", "by", inv.Human.Handle, "channel_id", inv.ChannelID)
		if !active {
			return "Debug in this channel: off (it was not on)."
		}
		return "Debug in this channel: off (was: " + describeDebug(cur, now) + ")."
	}
	d := ChannelDebug{ChannelID: inv.ChannelID, Categories: next, SetBy: inv.Human.Handle, SetByID: inv.Human.ID,
		SetAt: now, Until: now.Add(req.dur)}
	if err := s.Debug.Set(d); err != nil {
		s.Log.Error("set debug", "err", err, "channel_id", inv.ChannelID)
		return "Switching debug failed; try again."
	}
	s.Log.Info("set debug", "by", inv.Human.Handle, "channel_id", inv.ChannelID,
		"categories", strings.Join(next, ","), "until", d.Until.UTC().Format(time.RFC3339))
	out := "Debug in this channel: " + describeDebug(d, now)
	if active {
		out += " (was: " + quoteCategories(cur.Categories) + ", until " + fmtModeTime(cur.Until) + ")"
	}
	return out + ". Agents here pick it up the next time they fetch it; an agent counts it only when its session trusts you."
}

func describeDebug(d ChannelDebug, now time.Time) string {
	return fmt.Sprintf("%s, until %s (%s from now), set by @%s", quoteCategories(d.Categories), fmtModeTime(d.Until),
		fmtDur(d.Until.Sub(now)), d.SetBy)
}

func quoteCategories(cs []string) string {
	q := make([]string, len(cs))
	for i, c := range cs {
		q[i] = "`" + c + "`"
	}
	return strings.Join(q, " ")
}

func knownCategories() string { return quoteCategories(DebugCategories) + ", or `full` for all" }

// fmtDur shows a duration in whole minutes: 1h, 45m, 1h30m, 24h.
func fmtDur(d time.Duration) string {
	m := int(d.Round(time.Minute) / time.Minute)
	switch {
	case m >= 60 && m%60 == 0:
		return fmt.Sprintf("%dh", m/60)
	case m >= 60:
		return fmt.Sprintf("%dh%dm", m/60, m%60)
	default:
		return fmt.Sprintf("%dm", m)
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func debugUsage(trigger string) string {
	return "Debug shows, on an agent's posts in its home, what its own MCP server decided and why.\n\n" +
		"- `" + trigger + " on <category…> [for <duration>]`: add categories\n" +
		"- `" + trigger + " off <category…> [for <duration>]`: remove categories\n" +
		"- `" + trigger + " off`: turn all off\n" +
		"- `" + trigger + " full [for <duration>]`: turn all on\n" +
		"- `" + trigger + " set <category…> [for <duration>]`: replace the categories\n" +
		"- `" + trigger + "` or `" + trigger + " status`: show the categories and when they end\n\n" +
		"Categories: " + knownCategories() + ". Each command sets one new end for the whole setting: " +
		fmtDur(DebugDefault) + " from now, or what `for` names (at most " + fmtDur(DebugMax) + ").\n" +
		"The setting is published in a record that anyone can read without logging in."
}
