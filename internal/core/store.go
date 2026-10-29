package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TokenPrefix starts every enrollment token, so it is recognisable in logs
// and by secret scanners, and never mistaken for the shared secret.
const TokenPrefix = "mmenr_"

// Token is a stored enrollment token. The secret itself is never stored, only
// its keyed hash (HMAC-SHA256 with the server's pepper).
type Token struct {
	ID          string     `json:"id"`
	Hash        string     `json:"hash"`
	OwnerID     string     `json:"owner_id"`
	OwnerHandle string     `json:"owner_handle"` // at creation; for listing only
	Label       string     `json:"label,omitempty"`
	Kind        string     `json:"kind"`
	MaxBots     int        `json:"max_bots"`
	Channels    []string   `json:"channels,omitempty"` // empty: the default channel only
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// Active says whether the token may still be used at now.
func (t Token) Active(now time.Time) bool {
	return t.RevokedAt == nil && now.Before(t.ExpiresAt)
}

// inactiveSince is when the token stopped being usable: revoked or expired,
// whichever came first.
func (t Token) inactiveSince() time.Time {
	if t.RevokedAt != nil && t.RevokedAt.Before(t.ExpiresAt) {
		return *t.RevokedAt
	}
	return t.ExpiresAt
}

// AgentRecord is a bot registered with an enrollment token, kept until it is
// unregistered; it counts against the token's MaxBots.
type AgentRecord struct {
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	TokenID   string    `json:"token_id"`
	OwnerID   string    `json:"owner_id"`
	CreatedAt time.Time `json:"created_at"`
}

type state struct {
	Version int           `json:"version"`
	Tokens  []Token       `json:"tokens"`
	Agents  []AgentRecord `json:"agents"`
}

// Store keeps tokens and enrolled agents in memory and, with a path, in a
// JSON file written atomically (temp file + rename, mode 0600) after every
// change. One registrar process owns the file.
type Store struct {
	mu     sync.Mutex
	path   string
	pepper []byte
	st     state
}

// OpenStore loads path, or starts empty when it does not exist. An empty
// path keeps everything in memory (tests).
func OpenStore(path string, pepper []byte) (*Store, error) {
	if len(pepper) == 0 {
		return nil, errors.New("enrollment pepper is empty")
	}
	s := &Store{path: path, pepper: pepper, st: state{Version: 1}}
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
		return nil, fmt.Errorf("enrollment store %s: %w", path, err)
	}
	return s, nil
}

func (s *Store) hash(secret string) string {
	m := hmac.New(sha256.New, s.pepper)
	m.Write([]byte(secret))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".enrollments-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // a no-op after the rename
	err = tmp.Chmod(0o600)
	if err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomID() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Create stores t (its ID and Hash are set here) and returns the secret,
// which exists only in this return value.
func (s *Store) Create(t Token) (Token, string, error) {
	raw, err := randomString(32) // 256 bits
	if err != nil {
		return Token{}, "", err
	}
	secret := TokenPrefix + raw
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		id, err := randomID()
		if err != nil {
			return Token{}, "", err
		}
		if s.findLocked(id) < 0 {
			t.ID = id
			break
		}
	}
	t.Hash = s.hash(secret)
	s.st.Tokens = append(s.st.Tokens, t)
	if err := s.saveLocked(); err != nil {
		s.st.Tokens = s.st.Tokens[:len(s.st.Tokens)-1]
		return Token{}, "", err
	}
	return t, secret, nil
}

func (s *Store) findLocked(id string) int {
	for i, t := range s.st.Tokens {
		if t.ID == id {
			return i
		}
	}
	return -1
}

// Lookup finds the token a secret belongs to, active or not; ok is false
// when no stored hash matches.
func (s *Store) Lookup(secret string) (Token, bool) {
	h := []byte(s.hash(secret))
	s.mu.Lock()
	defer s.mu.Unlock()
	var found Token
	ok := false
	for _, t := range s.st.Tokens {
		if subtle.ConstantTimeCompare(h, []byte(t.Hash)) == 1 {
			found, ok = t, true
		}
	}
	return found, ok
}

// Owned lists the tokens of one owner, oldest first.
func (s *Store) Owned(ownerID string) []Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Token
	for _, t := range s.st.Tokens {
		if t.OwnerID == ownerID {
			out = append(out, t)
		}
	}
	return out
}

// Revoke revokes the owner's token id, or all of the owner's active tokens
// when id is "all". It returns how many it revoked.
func (s *Store) Revoke(ownerID, id string, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for i := range s.st.Tokens {
		t := &s.st.Tokens[i]
		if t.OwnerID != ownerID || t.RevokedAt != nil || (id != "all" && t.ID != id) {
			continue
		}
		at := now
		t.RevokedAt = &at
		n++
	}
	if n == 0 {
		return 0, nil
	}
	return n, s.saveLocked()
}

// Touch records that a token was used.
func (s *Store) Touch(id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i := s.findLocked(id); i >= 0 {
		at := now
		s.st.Tokens[i].LastUsedAt = &at
		return s.saveLocked()
	}
	return nil
}

// AgentsOf lists the agents a token has registered and not unregistered.
// These records are the token's bots: each names the bot's provider user id
// and the token it was enrolled with.
func (s *Store) AgentsOf(tokenID string) []AgentRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []AgentRecord
	for _, a := range s.st.Agents {
		if a.TokenID == tokenID {
			out = append(out, a)
		}
	}
	return out
}

// Prune forgets tokens that have been revoked or expired for at least
// retention and have no live bots left. A token whose bots are still
// recorded stays, so they keep their owner binding and can still be removed
// through it. It returns how many tokens it dropped.
func (s *Store) Prune(now time.Time, retention time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	live := map[string]bool{}
	for _, a := range s.st.Agents {
		live[a.TokenID] = true
	}
	kept := make([]Token, 0, len(s.st.Tokens))
	for _, t := range s.st.Tokens {
		if !t.Active(now) && !live[t.ID] && !now.Before(t.inactiveSince().Add(retention)) {
			continue
		}
		kept = append(kept, t)
	}
	n := len(s.st.Tokens) - len(kept)
	if n == 0 {
		return 0, nil
	}
	old := s.st.Tokens
	s.st.Tokens = kept
	if err := s.saveLocked(); err != nil {
		s.st.Tokens = old
		return 0, err
	}
	return n, nil
}

// LiveAgents counts the agents a token has registered and not unregistered.
func (s *Store) LiveAgents(tokenID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, a := range s.st.Agents {
		if a.TokenID == tokenID {
			n++
		}
	}
	return n
}

// AddAgent records an enrolled agent.
func (s *Store) AddAgent(a AgentRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Agents = append(s.st.Agents, a)
	return s.saveLocked()
}

// Agent returns the record of an enrolled agent by username.
func (s *Store) Agent(username string) (AgentRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.st.Agents {
		if a.Username == username {
			return a, true
		}
	}
	return AgentRecord{}, false
}

// RemoveAgent forgets an agent by username (unregistered or gone).
func (s *Store) RemoveAgent(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.st.Agents[:0]
	removed := false
	for _, a := range s.st.Agents {
		if a.Username == username {
			removed = true
			continue
		}
		kept = append(kept, a)
	}
	s.st.Agents = kept
	if !removed {
		return nil
	}
	return s.saveLocked()
}
