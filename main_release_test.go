package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dembaca/mattermost-agent-registrar/internal/core"
)

// releaseKey is "<typ> <base64>" of an Ed25519 key of 32 bytes b, with app
// for a security key.
func releaseKey(typ string, b byte, app string) string {
	var blob []byte
	put := func(v []byte) {
		blob = binary.BigEndian.AppendUint32(blob, uint32(len(v)))
		blob = append(blob, v...)
	}
	put([]byte(typ))
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	put(k)
	if app != "" {
		put([]byte(app))
	}
	return typ + " " + base64.StdEncoding.EncodeToString(blob)
}

func loadReleaseEnv(extra map[string]string) (config, error) {
	env := map[string]string{"MATTERMOST_URL": "http://mm", "MATTERMOST_TOKEN": "pat", "REGISTRATION_SECRET": "s",
		"ATTESTATION_KEY": base64.RawURLEncoding.EncodeToString(testSeed())}
	for k, v := range extra {
		if v == "-" {
			delete(env, k)
		} else {
			env[k] = v
		}
	}
	return loadConfig(func(k string) string { return env[k] })
}

func getRelease(h http.Handler) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/register/v1/release", nil))
	return rr
}

// releaseServer is a server from the environment extra (plus a key), its
// stores in a temp dir and its clock at now.
func releaseServer(t *testing.T, extra map[string]string, now time.Time) *server {
	t.Helper()
	cfg, err := loadReleaseEnv(extra)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := testAttestor(t)
	s := newDebugServer(t, a, nil, nil)
	s.svc.Release = cfg.release
	s.svc.Now = func() time.Time { return now }
	return s
}

func releaseClaims(t *testing.T, rr *httptest.ResponseRecorder, now time.Time) core.ReleaseClaims {
	t.Helper()
	if rr.Code != http.StatusOK || rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("release: %d %v %s", rr.Code, rr.Header(), rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || len(body) != 1 {
		t.Fatalf("body %s %v", rr.Body.String(), err)
	}
	_, pub := testAttestor(t)
	c, err := core.VerifyRelease(body["record"], pub, now)
	if err != nil {
		t.Fatal(err)
	}
	hdr, _ := base64.RawURLEncoding.DecodeString(strings.SplitN(body["record"], ".", 2)[0])
	a, _ := testAttestor(t)
	if string(hdr) != `{"alg":"EdDSA","typ":"mm-agent-release+jwt","kid":"`+a.Kid()+`"}` {
		t.Fatalf("header %s", hdr)
	}
	return c
}

func TestReleaseUnsetIs404(t *testing.T) {
	rr := getRelease(releaseServer(t, nil, time.Now()).routes())
	if rr.Code != http.StatusNotFound || rr.Body.String() != `{"error":"no release set"}`+"\n" ||
		rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("unset: %d %v %q", rr.Code, rr.Header(), rr.Body.String())
	}
}

func TestReleaseKeysOnly(t *testing.T) {
	k1, k2 := releaseKey("ssh-ed25519", 1, ""), releaseKey("sk-ssh-ed25519@openssh.com", 2, "ssh:")
	now := time.Now()
	s := releaseServer(t, map[string]string{"RELEASE_SIGNERS": k1 + " owner@laptop, " + k2 + " yubikey"}, now)
	rr := getRelease(s.routes())
	c := releaseClaims(t, rr, now)
	if !reflect.DeepEqual(c.Signers, []string{k1, k2}) || c.Version != "" || c.Iat != now.Unix() || c.Exp != now.Unix()+3600 ||
		c.SetAtMs != s.svc.Release.SetAt.UnixMilli() || c.SetAtMs == 0 {
		t.Fatalf("claims %+v", c)
	}
	// No version claim at all, and no comment.
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(strings.Split(rr.Body.String(), `"`)[3], ".")[1])
	if strings.Contains(string(payload), "version") || strings.Contains(string(payload), "laptop") ||
		!strings.HasPrefix(string(payload), `{"signers":[`) {
		t.Fatalf("payload %s", payload)
	}
}

func TestReleaseKeysAndVersion(t *testing.T) {
	k1, k2 := releaseKey("sk-ssh-ed25519@openssh.com", 2, "ssh:"), releaseKey("ssh-ed25519", 1, "")
	file := filepath.Join(t.TempDir(), "signers")
	if err := os.WriteFile(file, []byte("# release keys\n"+k1+" yubikey 5c\n"+k2+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s := releaseServer(t, map[string]string{"RELEASE_SIGNERS_FILE": file, "RELEASE_VERSION": "v0.86.0"}, now)
	rr := getRelease(s.routes())
	c := releaseClaims(t, rr, now)
	if !reflect.DeepEqual(c.Signers, []string{k1, k2}) || c.Version != "v0.86.0" {
		t.Fatalf("claims %+v", c)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(strings.Split(rr.Body.String(), `"`)[3], ".")[1])
	if !strings.HasPrefix(string(payload), `{"signers":["`+k1+`","`+k2+`"],"version":"v0.86.0","set_at_ms":`) {
		t.Fatalf("payload order %s", payload)
	}
}

func TestReleaseLatest(t *testing.T) {
	k := releaseKey("ssh-ed25519", 1, "")
	now := time.Now()
	s := releaseServer(t, map[string]string{"RELEASE_SIGNERS": k, "RELEASE_VERSION": "latest"}, now)
	rr := getRelease(s.routes())
	c := releaseClaims(t, rr, now)
	if !reflect.DeepEqual(c.Signers, []string{k}) || c.Version != "latest" {
		t.Fatalf("claims %+v", c)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(strings.Split(rr.Body.String(), `"`)[3], ".")[1])
	if !strings.HasPrefix(string(payload), `{"signers":["`+k+`"],"version":"latest","set_at_ms":`) {
		t.Fatalf("payload %s", payload)
	}
	if _, err := loadReleaseEnv(map[string]string{"RELEASE_VERSION": "latest"}); err == nil ||
		!strings.Contains(err.Error(), "RELEASE_VERSION needs RELEASE_SIGNERS") {
		t.Fatalf("latest without signers: %v", err)
	}
	for _, v := range []string{"Latest", "LATEST", "v-latest", "vlatest"} {
		_, err := loadReleaseEnv(map[string]string{"RELEASE_SIGNERS": k, "RELEASE_VERSION": v})
		if err == nil || !strings.Contains(err.Error(), "RELEASE_VERSION: not v<x.y.z> without leading zeros, like v0.86.0, or latest") {
			t.Errorf("%q: %v", v, err)
		}
	}
}

func TestLoadConfigRelease(t *testing.T) {
	k := releaseKey("ssh-ed25519", 1, "")
	file := filepath.Join(t.TempDir(), "signers")
	if err := os.WriteFile(file, []byte(k+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadReleaseEnv(nil)
	if err != nil || cfg.release != nil || cfg.releaseRateLimitPerMin != 120 {
		t.Fatalf("unset: %+v %v", cfg.release, err)
	}
	before := time.Now()
	cfg, err = loadReleaseEnv(map[string]string{"RELEASE_SIGNERS": k + " a comment"})
	if err != nil || !reflect.DeepEqual(cfg.release.Signers, []string{k}) || cfg.release.Version != "" ||
		cfg.release.SetAt.Before(before) {
		t.Fatalf("keys only: %+v %v", cfg.release, err)
	}
	refused := map[string]map[string]string{
		"type must be ssh-ed25519":              {"RELEASE_SIGNERS": "ssh-rsa " + strings.SplitN(k, " ", 2)[1]},
		"RELEASE_VERSION: not v<x.y.z>":         {"RELEASE_SIGNERS": k, "RELEASE_VERSION": "0.86.0"},
		"RELEASE_VERSION needs RELEASE_SIGNERS": {"RELEASE_VERSION": "v0.86.0"},
		"RELEASE_VERSION: not v<x.y.z> without leading zeros, like v0.86.0, or latest": {"RELEASE_SIGNERS": k, "RELEASE_VERSION": "Latest"},
		"set RELEASE_SIGNERS or RELEASE_SIGNERS_FILE, not both":                        {"RELEASE_SIGNERS": k, "RELEASE_SIGNERS_FILE": file},
		"RELEASE_SIGNERS needs ATTESTATION_KEY":                                        {"RELEASE_SIGNERS": k, "ATTESTATION_KEY": "-"},
		"RELEASE_SIGNERS_FILE: cannot read":                                            {"RELEASE_SIGNERS_FILE": file + ".missing"},
		"RELEASE_SIGNERS: key 1: key data":                                             {"RELEASE_SIGNERS": "ssh-ed25519 AAAA"},
	}
	for want, env := range refused {
		_, err := loadReleaseEnv(env)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: %v, want %q", env, err, want)
		}
		if err != nil && strings.Contains(err.Error(), strings.SplitN(k, " ", 2)[1][:16]) {
			t.Errorf("%v: error carries key material: %v", env, err)
		}
	}
	// A bad version and bad signers are reported together.
	_, err = loadReleaseEnv(map[string]string{"RELEASE_SIGNERS": "ssh-rsa AAAA", "RELEASE_VERSION": "v01.0.0"})
	if err == nil || !strings.Contains(err.Error(), "RELEASE_VERSION: not") || !strings.Contains(err.Error(), "RELEASE_SIGNERS: key 1") {
		t.Fatalf("both errors: %v", err)
	}
	// The file is capped at 64 KiB.
	big := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(big, []byte(k+"\n"+strings.Repeat("#", 64<<10)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadReleaseEnv(map[string]string{"RELEASE_SIGNERS_FILE": big}); err == nil || !strings.Contains(err.Error(), "larger than 64 KiB") {
		t.Fatalf("big file: %v", err)
	}
	// Version needs signers also with the key: a version alone never publishes.
	if _, err := loadReleaseEnv(map[string]string{"RELEASE_VERSION": "v0.86.0", "ATTESTATION_KEY": "-"}); err == nil {
		t.Fatal("version alone without key accepted")
	}
}

func TestReleaseRouteNeedsAttestationKey(t *testing.T) {
	// No attestation key: no route, even with a release set.
	s := newDebugServer(t, nil, nil, nil)
	s.svc.Release = &core.Release{Signers: []string{releaseKey("ssh-ed25519", 1, "")}, SetAt: time.Now()}
	if rr := getRelease(s.routes()); rr.Code != http.StatusNotFound || strings.Contains(rr.Body.String(), "no release set") {
		t.Fatalf("GET without key: %d %s", rr.Code, rr.Body.String())
	}
	// newServer passes the release on only with a key.
	a, _ := testAttestor(t)
	s = newDebugServer(t, a, nil, nil)
	if s.svc.Release != nil {
		t.Fatal("release without config")
	}
}

func TestReleaseRecordHasItsOwnRateBucket(t *testing.T) {
	s := releaseServer(t, nil, time.Now())
	s.rate, s.debugRate, s.releaseRate = newLimiter(2), newLimiter(50), newLimiter(3)
	h := s.routes()
	for i := 0; i < 3; i++ {
		if rr := getRelease(h); rr.Code != http.StatusNotFound {
			t.Fatalf("release get %d: %d", i, rr.Code)
		}
	}
	if rr := getRelease(h); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("release bucket not enforced: %d", rr.Code)
	}
	if rr := getDebug(h, modeChan); rr.Code != http.StatusNotFound {
		t.Fatalf("debug bucket drained by release: %d", rr.Code)
	}
}
