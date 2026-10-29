package core

import (
	"context"
	"strconv"
	"strings"
)

// Description markers. The bus parses them (its profile.py): "for @<owner>"
// names the bound owner, "trusts @a, @b" the trusted humans, a trailing
// "+N" in that list says N further names were not written. A bot without an
// owner binding starts with "unbound" and has no "for @".
const (
	via          = "via agent-registrar"
	unboundMark  = "unbound"
	maxDescLen   = 1024
	partSep      = " · "
	trustsPrefix = "trusts @"
)

// describe builds the bot's description:
//
//	bound:   for @alice · autonomous · trusts @alice, @bob +2 · via agent-registrar
//	unbound: unbound · claims @alice · trusts @alice · via agent-registrar
//
// The owner of a bound bot comes from its enrollment token. An unbound bot
// (shared secret) records the caller's unchecked claim as "claims @…", never
// as "for @…". Every name must be an existing human; others are left out.
// "autonomous" appears only for that kind.
func (s *Service) describe(ctx context.Context, owner *Human, claimed, kind string, trusted []string) string {
	human := func(raw string) (string, bool) {
		n := normHandle(raw)
		if !userRE.MatchString(n) {
			return "", false
		}
		h, err := s.Provider.ResolveHuman(ctx, n)
		if err != nil || h == nil {
			s.Log.Info("profile: not a human user, left out", "name", n, "err", err)
			return "", false
		}
		return h.Handle, true
	}
	var parts []string
	if owner != nil {
		parts = append(parts, "for @"+owner.Handle)
	} else {
		parts = append(parts, unboundMark)
		if n, ok := human(claimed); ok {
			parts = append(parts, "claims @"+n)
		}
	}
	if kind == "autonomous" {
		parts = append(parts, "autonomous")
	}
	names, more := s.trusted(trusted, human)
	if len(names) > 0 || more > 0 {
		// With no name written, "trusts @ +N" still parses as a cut list.
		t := trustsPrefix + strings.Join(names, ", @")
		if more > 0 {
			t += " +" + strconv.Itoa(more)
		}
		parts = append(parts, t)
	}
	d := strings.Join(append(parts, via), partSep)
	if len(d) > maxDescLen {
		d = d[:maxDescLen]
	}
	return d
}

// trusted resolves up to Policy.MaxTrusted distinct human names and counts
// the distinct well-formed names beyond the cap it did not check.
func (s *Service) trusted(raw []string, human func(string) (string, bool)) ([]string, int) {
	limit := s.Policy.MaxTrusted
	var names []string
	seen := map[string]bool{}
	more := 0
	for _, r := range raw {
		n := normHandle(r)
		if !userRE.MatchString(n) || seen[n] {
			continue
		}
		seen[n] = true
		if len(names) >= limit {
			more++
			continue
		}
		if h, ok := human(n); ok {
			names = append(names, h)
		}
	}
	return names, more
}
