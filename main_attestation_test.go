package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dembaca/mattermost-agent-registrar/internal/core"
)

func getAttestation(h http.Handler, id string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/register/v1/attestations/"+id, nil))
	return rr
}

func TestAttestationRecordOverHTTP(t *testing.T) {
	a, pub := testAttestor(t)
	h := newMandateServer(t, a, nil, nil).routes()

	rr := post(h, "/register/v1/agents", "secret", `{"name":"att-1","responsible":"@Alice"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("register: %d %s", rr.Code, rr.Body.String())
	}
	var reg registerResp
	if err := json.Unmarshal(rr.Body.Bytes(), &reg); err != nil {
		t.Fatal(err)
	}

	got := getAttestation(h, reg.UserID)
	if got.Code != http.StatusOK || got.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("read: %d %s", got.Code, got.Body.String())
	}
	var body struct {
		Record string `json:"record"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil || body.Record == "" {
		t.Fatalf("answer: %s %v", got.Body.String(), err)
	}
	c, err := core.VerifyAttestation(body.Record, pub, time.Now())
	if err != nil || c.BotID != reg.UserID || c.Username != reg.Username || c.Responsible != "alice" || c.Via != core.ViaSecret {
		t.Fatalf("claims: %+v %v", c, err)
	}
	if c.Exp-c.Iat != int64(core.AttestationTTL/time.Second) {
		t.Fatalf("expiry: %d", c.Exp-c.Iat)
	}

	// Only the registrar's own body means none.
	none := getAttestation(h, "nobody")
	if none.Code != http.StatusNotFound || strings.TrimSpace(none.Body.String()) != `{"error":"no attestation"}` {
		t.Fatalf("unknown: %d %s", none.Code, none.Body.String())
	}
	if bad := getAttestation(h, "bad%20id"); bad.Code != http.StatusBadRequest || strings.Contains(bad.Body.String(), "no attestation") {
		t.Fatalf("bad id: %d %s", bad.Code, bad.Body.String())
	}

	// Removed through the registrar: none again.
	del := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/register/v1/agents/att-1", nil)
	req.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(del, req)
	if del.Code >= 300 {
		t.Fatalf("unregister: %d %s", del.Code, del.Body.String())
	}
	if gone := getAttestation(h, reg.UserID); gone.Code != http.StatusNotFound || !strings.Contains(gone.Body.String(), "no attestation") {
		t.Fatalf("after unregister: %d %s", gone.Code, gone.Body.String())
	}
}

func TestAttestationRouteFollowsTheKeyAndHasItsOwnRateBucket(t *testing.T) {
	a, _ := testAttestor(t)
	h := newMandateServer(t, nil, nil, nil).routes()
	if rr := getAttestation(h, "x"); rr.Code != http.StatusNotFound || strings.Contains(rr.Body.String(), "no attestation") {
		t.Fatalf("without a key it is no registrar answer: %d %s", rr.Code, rr.Body.String())
	}
	s := newMandateServer(t, a, nil, nil)
	s.attestationRate = newLimiter(2)
	h = s.routes()
	for i, want := range []int{http.StatusNotFound, http.StatusNotFound, http.StatusTooManyRequests} {
		if rr := getAttestation(h, "x"); rr.Code != want {
			t.Fatalf("request %d: %d", i, rr.Code)
		}
	}
	if rr := getMandate(h, modeChan); rr.Code == http.StatusTooManyRequests {
		t.Fatal("the mandate bucket is shared")
	}
}

// failingFind is a provider that cannot tell whether a bot exists.
type failingFind struct{ core.ProviderPort }

func (failingFind) FindAgent(context.Context, string) (*core.Agent, error) {
	return nil, errors.New("mattermost is down")
}

func TestAttestationLookupFailureIsNoNotFound(t *testing.T) {
	a, _ := testAttestor(t)
	s := newMandateServer(t, a, nil, nil)
	h := s.routes()
	rr := post(h, "/register/v1/agents", "secret", `{"name":"att-2"}`)
	var reg registerResp
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &reg) != nil {
		t.Fatalf("register: %d %s", rr.Code, rr.Body.String())
	}
	s.svc.Provider = failingFind{s.svc.Provider}
	got := getAttestation(h, reg.UserID)
	if got.Code != http.StatusBadGateway || strings.Contains(got.Body.String(), "no attestation") ||
		strings.Contains(got.Body.String(), "mattermost is down") {
		t.Fatalf("lookup failure: %d %s", got.Code, got.Body.String())
	}
}
