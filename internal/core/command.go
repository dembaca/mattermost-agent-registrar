package core

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Command runs the token command for a verified invocation and returns the
// private reply: create, list, revoke or help.
func (s *Service) Command(ctx context.Context, inv Invocation) string {
	if s.Store == nil {
		return "Enrollment tokens are not enabled on this registrar."
	}
	trigger := inv.Command
	if trigger == "" {
		trigger = "/<command>"
	}
	args, err := splitArgs(inv.Text)
	if err != nil {
		return err.Error() + "\n\n" + usage(trigger)
	}
	if len(args) == 0 {
		return usage(trigger)
	}
	switch strings.ToLower(args[0]) {
	case "create":
		return s.create(ctx, inv, trigger, args[1:])
	case "list":
		return s.list(inv)
	case "revoke":
		if len(args) != 2 {
			return "Usage: `" + trigger + " revoke <id|all>`"
		}
		return s.revoke(ctx, inv, trigger, strings.ToLower(args[1]))
	}
	return usage(trigger)
}

// revoke revokes the caller's token id (or all of them) and unregisters the
// bots registered with the matching revoked tokens, through the same path as
// Unregister. A bot that cannot be removed is reported and stays recorded, so
// running the revoke again retries it.
func (s *Service) revoke(ctx context.Context, inv Invocation, trigger, which string) string {
	// Serialised with enrollments: no bot is enrolled with a token after its
	// bots were collected here.
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	n, err := s.Store.Revoke(inv.Human.ID, which, s.now())
	if err != nil {
		s.Log.Error("revoke", "err", err)
		return "Revoking failed; try again."
	}
	removed := 0
	var failed []string
	for _, t := range s.Store.Owned(inv.Human.ID) {
		if t.RevokedAt == nil || (which != "all" && t.ID != which) {
			continue
		}
		for _, a := range s.Store.AgentsOf(t.ID) {
			ok, err := s.unregisterEnrolled(ctx, a)
			if err != nil {
				s.Log.Warn("unregister bot of revoked token", "err", err, "username", a.Username, "token_id", t.ID)
				failed = append(failed, "@"+a.Username)
				continue
			}
			if ok {
				removed++
			}
		}
	}
	if n == 0 && removed == 0 && len(failed) == 0 {
		return "No active token of yours matches `" + which + "`."
	}
	s.Log.Info("revoked enrollment tokens", "owner", inv.Human.Handle, "which", which, "count", n,
		"bots_removed", removed, "bots_failed", len(failed))
	out := fmt.Sprintf("Revoked %d token(s); unregistered %d bot(s) registered with them.", n, removed)
	if len(failed) > 0 {
		out += fmt.Sprintf(" Unregistering %d bot(s) failed (%s); run `%s revoke %s` again to retry.",
			len(failed), strings.Join(failed, ", "), trigger, which)
	}
	return out
}

func usage(trigger string) string {
	return "Enrollment tokens let an agent register a bot that is bound to you.\n\n" +
		"- `" + trigger + " create [--expires 30d] [--max-bots N] [--channels a,b] [--kind session|autonomous] [--label text]`\n" +
		"- `" + trigger + " list`\n" +
		"- `" + trigger + " revoke <id|all>` (also unregisters the bots registered with it)"
}

func (s *Service) create(ctx context.Context, inv Invocation, trigger string, args []string) string {
	p := s.Policy
	t := Token{
		OwnerID:     inv.Human.ID,
		OwnerHandle: inv.Human.Handle,
		Kind:        "session",
		MaxBots:     p.DefaultMaxBots,
	}
	ttl := p.DefaultTTL
	for i := 0; i < len(args); i++ {
		flag, val, inline := strings.Cut(args[i], "=")
		flag = strings.ToLower(flag)
		if !strings.HasPrefix(flag, "--") {
			return "Unexpected `" + args[i] + "`.\n\n" + usage(trigger)
		}
		if !inline {
			if i+1 >= len(args) {
				return "`" + flag + "` needs a value."
			}
			i++
			val = args[i]
		}
		switch flag {
		case "--expires":
			d, err := parseTTL(val)
			if err != nil || d <= 0 {
				return "`--expires` takes a duration like 30d, 12h or 2w."
			}
			if d > p.MaxTTL {
				return fmt.Sprintf("`--expires` may be at most %s on this registrar.", fmtTTL(p.MaxTTL))
			}
			ttl = d
		case "--max-bots":
			n, err := strconv.Atoi(val)
			if err != nil || n < 1 || n > p.MaxBotsLimit {
				return fmt.Sprintf("`--max-bots` takes a number from 1 to %d.", p.MaxBotsLimit)
			}
			t.MaxBots = n
		case "--channels":
			chans, err := normChannels(strings.Split(val, ","))
			if err != nil {
				return strings.TrimPrefix(err.Error(), ErrBadRequest.Error()+": ") + "."
			}
			t.Channels = chans
		case "--kind":
			k, err := normKind(val)
			if err != nil || k == "" {
				return "`--kind` is session or autonomous."
			}
			t.Kind = k
		case "--label":
			if len(val) > 64 {
				return "`--label` may have at most 64 characters."
			}
			t.Label = val
		default:
			return "Unknown option `" + flag + "`.\n\n" + usage(trigger)
		}
	}
	now := s.now()
	active := 0
	for _, o := range s.Store.Owned(inv.Human.ID) {
		if o.Active(now) {
			active++
		}
	}
	if active >= p.MaxTokensPerUser {
		return fmt.Sprintf("You have %d active tokens, the most allowed. Revoke one first.", active)
	}
	check := t.Channels
	if len(check) == 0 {
		check = []string{p.DefaultChannel}
	}
	for _, c := range check {
		ok, err := s.Provider.HumanCanAccess(ctx, inv.Human, c)
		if errors.Is(err, ErrNoSuchChannel) {
			return "Channel `" + c + "` does not exist."
		}
		if err != nil {
			s.Log.Error("channel check", "err", err, "channel", c)
			return "Checking your channel access failed; try again."
		}
		if !ok {
			return "You have no access to channel `" + c + "`; a token can only cover channels you can read."
		}
	}
	t.CreatedAt = now
	t.ExpiresAt = now.Add(ttl)
	stored, secret, err := s.Store.Create(t)
	if err != nil {
		s.Log.Error("create enrollment token", "err", err)
		return "Creating the token failed; try again."
	}
	s.Log.Info("created enrollment token", "owner", inv.Human.Handle, "token_id", stored.ID,
		"kind", stored.Kind, "max_bots", stored.MaxBots, "channels", strings.Join(check, ","), "expires", stored.ExpiresAt)
	return fmt.Sprintf("Enrollment token `%s` created. It is shown only now; copy it:\n\n```\n%s\n```\n\n%s\n\n"+
		"Give it to your agent as its registration secret (the Bearer credential of `POST /register/v1/agents`). "+
		"Every bot it registers is bound to you. Revoke it with `%s revoke %s`.",
		stored.ID, secret, scopeLine(stored, check), trigger, stored.ID)
}

func scopeLine(t Token, channels []string) string {
	s := fmt.Sprintf("Owner @%s · kind %s · up to %d bots · channels %s · expires %s",
		t.OwnerHandle, t.Kind, t.MaxBots, strings.Join(channels, ", "), t.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"))
	if t.Label != "" {
		s += " · label " + t.Label
	}
	return s
}

func (s *Service) list(inv Invocation) string {
	now := s.now()
	var rows []string
	inactive := 0
	for _, t := range s.Store.Owned(inv.Human.ID) {
		if !t.Active(now) {
			inactive++
			continue
		}
		chans := strings.Join(t.Channels, ", ")
		if chans == "" {
			chans = s.Policy.DefaultChannel
		}
		used := "never"
		if t.LastUsedAt != nil {
			used = t.LastUsedAt.UTC().Format("2006-01-02 15:04")
		}
		rows = append(rows, fmt.Sprintf("| `%s` | %s | %s | %d/%d | %s | %s | %s |",
			t.ID, t.Label, t.Kind, s.Store.LiveAgents(t.ID), t.MaxBots, chans,
			t.ExpiresAt.UTC().Format("2006-01-02 15:04"), used))
	}
	if len(rows) == 0 {
		out := "You have no active enrollment tokens."
		if inactive > 0 {
			out += fmt.Sprintf(" (%d expired or revoked.)", inactive)
		}
		return out
	}
	out := "| id | label | kind | bots | channels | expires (UTC) | last used (UTC) |\n|---|---|---|---|---|---|---|\n" +
		strings.Join(rows, "\n")
	if inactive > 0 {
		out += fmt.Sprintf("\n\n%d expired or revoked token(s) not shown.", inactive)
	}
	return out
}

// parseTTL reads 30d, 2w, 12h or any time.ParseDuration value.
func parseTTL(v string) (time.Duration, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	for suffix, unit := range map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour} {
		if n, ok := strings.CutSuffix(v, suffix); ok {
			i, err := strconv.Atoi(n)
			if err != nil {
				return 0, err
			}
			return time.Duration(i) * unit, nil
		}
	}
	return time.ParseDuration(v)
}

// ParseTTL is parseTTL for the configuration.
func ParseTTL(v string) (time.Duration, error) { return parseTTL(v) }

func fmtTTL(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return strconv.Itoa(int(d/(24*time.Hour))) + "d"
	}
	return d.String()
}

// splitArgs splits on spaces, keeping "double" or 'single' quoted parts whole.
func splitArgs(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	var quote rune
	inArg := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'' || r == '“' || r == '”':
			if r == '“' || r == '”' {
				r = '”'
			}
			quote, inArg = r, true
		case r == ' ' || r == '\t' || r == '\n':
			if inArg {
				out = append(out, cur.String())
				cur.Reset()
				inArg = false
			}
		default:
			cur.WriteRune(r)
			inArg = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unclosed quote")
	}
	if inArg {
		out = append(out, cur.String())
	}
	return out, nil
}
