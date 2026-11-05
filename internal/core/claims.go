package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"
)

// botIDRE is the shape of a provider user id in the path: nothing else is looked up.
var botIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// AttestationTTL is how long a record from GET /register/v1/attestations/…
// is valid: it is signed fresh for each read, so it stays short.
const AttestationTTL = time.Hour

// ClaimRecord is what the registrar accepted about a bot when it registered
// it: the claims of its attestation, kept until the bot is removed. The
// attestation endpoint signs them afresh; nothing signed is stored.
type ClaimRecord struct {
	BotID       string    `json:"bot_id"`
	Username    string    `json:"username"`
	Responsible string    `json:"responsible"`
	Trusted     []string  `json:"trusted"`
	TrustedCut  int       `json:"trusted_cut,omitempty"`
	Kind        string    `json:"kind"`
	Via         string    `json:"via"`
	CreatedAt   time.Time `json:"created_at"`
}

type claimState struct {
	Version int                    `json:"version"`
	Bots    map[string]ClaimRecord `json:"bots"` // by bot id
}

// ClaimStore keeps the claim record per bot in memory and, with a path, in
// its own JSON file, written atomically (temp file + rename, mode 0600) after
// every change. It is separate from the enrollment store, so the secret path
// is recorded as well. One registrar process owns the file.
type ClaimStore struct {
	mu   sync.Mutex
	path string
	st   claimState
}

// OpenClaimStore loads path, or starts empty when it does not exist. An
// empty path keeps everything in memory (tests).
func OpenClaimStore(path string) (*ClaimStore, error) {
	s := &ClaimStore{path: path, st: claimState{Version: 1, Bots: map[string]ClaimRecord{}}}
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
		return nil, fmt.Errorf("attestation store %s: %w", path, err)
	}
	if s.st.Bots == nil {
		s.st.Bots = map[string]ClaimRecord{}
	}
	return s, nil
}

// Get returns the record of a bot; ok is false when there is none.
func (s *ClaimStore) Get(botID string) (ClaimRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.st.Bots[botID]
	return r, ok
}

// Put stores r as its bot's record, replacing any earlier one.
func (s *ClaimStore) Put(r ClaimRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, had := s.st.Bots[r.BotID]
	s.st.Bots[r.BotID] = r
	if err := s.saveLocked(); err != nil {
		if had {
			s.st.Bots[r.BotID] = old
		} else {
			delete(s.st.Bots, r.BotID)
		}
		return err
	}
	return nil
}

// Remove forgets the record of a bot id (none: no-op).
func (s *ClaimStore) Remove(botID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removeLocked(func(r ClaimRecord) bool { return r.BotID == botID })
}

// RemoveUsername forgets the records of a username, for a bot that is gone
// and whose id is no longer at hand.
func (s *ClaimStore) RemoveUsername(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removeLocked(func(r ClaimRecord) bool { return r.Username == username })
}

func (s *ClaimStore) removeLocked(match func(ClaimRecord) bool) error {
	old := map[string]ClaimRecord{}
	for id, r := range s.st.Bots {
		if match(r) {
			old[id] = r
		}
	}
	if len(old) == 0 {
		return nil
	}
	for id := range old {
		delete(s.st.Bots, id)
	}
	if err := s.saveLocked(); err != nil {
		for id, r := range old {
			s.st.Bots[id] = r
		}
		return err
	}
	return nil
}

func (s *ClaimStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, ".attestations-*", data)
}

// SignFor stamps iat (now) and exp (now + ttl) on c and returns the compact
// JWS; Sign uses the attestor's own, longer TTL (the registration's).
func (a *Attestor) SignFor(c AttestClaims, now time.Time, ttl time.Duration) (string, error) {
	c.Iat = now.Unix()
	c.Exp = now.Add(ttl).Unix()
	return a.SignExact(c)
}

// forget drops the claim record of a bot that is removed.
func (s *Service) forget(agent Agent) {
	if s.Claims == nil {
		return
	}
	if err := s.Claims.Remove(agent.ID); err != nil {
		s.Log.Warn("forget claims", "err", err, "username", agent.Username)
	}
}

// remember keeps what the registrar accepted about a bot, for the attestation
// endpoint. A failure is logged: the registration itself stands, the bot has
// no attestation to read until it is registered again.
func (s *Service) remember(c AttestClaims) {
	if s.Claims == nil {
		return
	}
	if c.Trusted == nil {
		c.Trusted = []string{}
	}
	err := s.Claims.Put(ClaimRecord{BotID: c.BotID, Username: c.Username, Responsible: c.Responsible,
		Trusted: c.Trusted, TrustedCut: c.TrustedCut, Kind: c.Kind, Via: c.Via, CreatedAt: s.now()})
	if err != nil {
		s.Log.Error("record claims", "err", err, "username", c.Username)
	}
}

// AttestationRecord returns the signed attestation of a bot, signed now with
// a short expiry. ErrBadRequest for an invalid bot id, ErrNoAttestation when
// none is recorded, the bot is gone, or attestations are off; ErrUpstream when
// the provider cannot say whether the bot still exists.
func (s *Service) AttestationRecord(ctx context.Context, botID string) (string, error) {
	if !botIDRE.MatchString(botID) {
		return "", fmt.Errorf("%w: invalid bot id", ErrBadRequest)
	}
	if s.Claims == nil || s.Attestor == nil {
		return "", ErrNoAttestation
	}
	rec, ok := s.Claims.Get(botID)
	if !ok {
		return "", ErrNoAttestation
	}
	agent, err := s.Provider.FindAgent(ctx, rec.Username)
	if err != nil {
		return "", fmt.Errorf("%w: lookup: %v", ErrUpstream, err)
	}
	if agent == nil || agent.ID != rec.BotID {
		// Removed outside the registrar: no claim outlives its bot.
		if err := s.Claims.Remove(botID); err != nil {
			s.Log.Warn("forget claims", "err", err, "username", rec.Username)
		}
		return "", ErrNoAttestation
	}
	return s.Attestor.SignFor(AttestClaims{BotID: rec.BotID, Username: rec.Username,
		Responsible: rec.Responsible, Trusted: rec.Trusted, TrustedCut: rec.TrustedCut,
		Kind: rec.Kind, Via: rec.Via}, s.now(), AttestationTTL)
}
