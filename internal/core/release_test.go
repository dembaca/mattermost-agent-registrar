package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// sshKey builds "<typ> <base64>" for an Ed25519 key with the given 32 bytes,
// plus app for a security key.
func sshKey(typ string, key []byte, app string) string {
	var blob []byte
	put := func(b []byte) {
		blob = binary.BigEndian.AppendUint32(blob, uint32(len(b)))
		blob = append(blob, b...)
	}
	put([]byte(typ))
	put(key)
	if app != "" {
		put([]byte(app))
	}
	return typ + " " + base64.StdEncoding.EncodeToString(blob)
}

func keyBytes(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

const releaseVectorHeader = `{"alg":"EdDSA","typ":"mm-agent-release+jwt","kid":"Vkdap1RjR0wChd9d"}`

func TestReleaseSignVerify(t *testing.T) {
	a, _ := NewAttestor(vectorSeed(), 30*24*time.Hour)
	k1, k2 := sshKey("ssh-ed25519", keyBytes(1), ""), sshKey("sk-ssh-ed25519@openssh.com", keyBytes(2), "ssh:")
	full := ReleaseClaims{Signers: []string{k1, k2}, Version: "v0.86.0", SetAtMs: 1699999000000, Iat: 1700000000, Exp: 1700003600}
	want := `{"signers":["` + k1 + `","` + k2 + `"],"version":"v0.86.0","set_at_ms":1699999000000,"iat":1700000000,"exp":1700003600}`
	if pb, _ := json.Marshal(full); string(pb) != want {
		t.Fatalf("payload:\n got  %s\n want %s", pb, want)
	}
	// Keys only: no version claim at all.
	keysOnly := full
	keysOnly.Version = ""
	if pb, _ := json.Marshal(keysOnly); strings.Contains(string(pb), "version") {
		t.Fatalf("keys-only payload has a version: %s", pb)
	}
	tok, err := a.SignReleaseExact(full)
	if err != nil {
		t.Fatal(err)
	}
	seg := b64.EncodeToString([]byte(releaseVectorHeader)) + "." + b64.EncodeToString([]byte(want))
	if !strings.HasPrefix(tok, seg) {
		t.Fatal("header or payload segment differs")
	}
	c, err := VerifyRelease(tok, vectorPub(), time.Unix(1700000000, 0))
	if err != nil || !reflect.DeepEqual(c, full) {
		t.Fatalf("verify: %+v %v", c, err)
	}
	if _, err := VerifyRelease(tok, vectorPub(), time.Unix(1700003600, 0)); err == nil {
		t.Fatal("expired record accepted")
	}
	bad := []byte(tok)
	bad[len(bad)-3] ^= 1
	if _, err := VerifyRelease(string(bad), vectorPub(), time.Unix(1700000000, 0)); err == nil {
		t.Fatal("tampered record accepted")
	}
	// Same key, other typ: a release record never passes as a debug record, nor back.
	if _, err := VerifyDebug(tok, vectorPub(), time.Unix(1700000000, 0)); err == nil {
		t.Fatal("release record passed as debug record")
	}
	dbg, _ := a.SignDebugExact(debugVectorClaims())
	if _, err := VerifyRelease(dbg, vectorPub(), time.Unix(1700000000, 0)); err == nil {
		t.Fatal("debug record passed as release record")
	}
	// SignRelease: exp is iat + 1 h.
	now := time.Unix(1700000000, 0)
	tok, _ = a.SignRelease(ReleaseClaims{Signers: []string{k1}}, now)
	if c, err := VerifyRelease(tok, vectorPub(), now); err != nil || c.Iat != now.Unix() || c.Exp != now.Unix()+3600 || c.Version != "" {
		t.Fatalf("SignRelease: %+v %v", c, err)
	}
}

func TestReleaseRecordFromService(t *testing.T) {
	a, _ := NewAttestor(vectorSeed(), time.Hour)
	now := time.Unix(1700000000, 0)
	s := &Service{Attestor: a, Now: func() time.Time { return now }}
	if _, err := s.ReleaseRecord(); err != ErrNoRelease {
		t.Fatalf("unset: %v", err)
	}
	k := sshKey("ssh-ed25519", keyBytes(1), "")
	s.Release = &Release{Signers: []string{k}, Version: "v1.2.3", SetAt: now.Add(-time.Minute)}
	tok, err := s.ReleaseRecord()
	if err != nil {
		t.Fatal(err)
	}
	c, err := VerifyRelease(tok, vectorPub(), now)
	if err != nil || !reflect.DeepEqual(c, ReleaseClaims{Signers: []string{k}, Version: "v1.2.3",
		SetAtMs: now.Add(-time.Minute).UnixMilli(), Iat: now.Unix(), Exp: now.Unix() + 3600}) {
		t.Fatalf("record: %+v %v", c, err)
	}
	s.Attestor = nil
	if _, err := s.ReleaseRecord(); err != ErrNoRelease {
		t.Fatalf("no attestor: %v", err)
	}
}

func TestParseReleaseSigners(t *testing.T) {
	k1 := sshKey("ssh-ed25519", keyBytes(1), "")
	k2 := sshKey("sk-ssh-ed25519@openssh.com", keyBytes(2), "ssh:")
	k3 := sshKey("ssh-ed25519", keyBytes(3), "")
	got, err := ParseReleaseSigners("# release keys\n"+k1+" owner@laptop\n\n"+k2+" yubikey 5c, "+k3, true)
	if err != nil || !reflect.DeepEqual(got, []string{k1, k2, k3}) {
		t.Fatalf("parse: %q %v", got, err)
	}
	// A file is one key per line: its comments may hold commas.
	got, err = ParseReleaseSigners("# keys, all of them\n"+k1+" owner, laptop\n"+k2+" yubikey, 5c", false)
	if err != nil || !reflect.DeepEqual(got, []string{k1, k2}) {
		t.Fatalf("file: %q %v", got, err)
	}
	if _, err := ParseReleaseSigners(k1+", "+k3, false); err == nil {
		t.Fatal("a comma-separated file line passed")
	}
	// At most MaxReleaseSigners.
	var many []string
	for i := 0; i <= MaxReleaseSigners; i++ {
		many = append(many, sshKey("ssh-ed25519", keyBytes(byte(10+i)), ""))
	}
	if got, err := ParseReleaseSigners(strings.Join(many[:MaxReleaseSigners], "\n"), false); err != nil || len(got) != MaxReleaseSigners {
		t.Fatalf("16 keys: %d %v", len(got), err)
	}
	if _, err := ParseReleaseSigners(strings.Join(many, ","), true); err == nil || !strings.Contains(err.Error(), "more than 16 keys") {
		t.Fatalf("17 keys: %v", err)
	}
	// Strict base64: nonzero padding bits are refused, not read as the same key.
	b := strings.SplitN(k2, " ", 2)[1]
	i := strings.IndexByte(b, '=') - 1
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	loose := b[:i] + string(alpha[strings.IndexByte(alpha, b[i])+1]) + b[i+1:]
	if _, err := ParseReleaseSigners("sk-ssh-ed25519@openssh.com "+loose, true); err == nil || !strings.Contains(err.Error(), "not base64") {
		t.Fatalf("loose base64: %v", err)
	}
	rsa := "ssh-rsa " + strings.SplitN(k1, " ", 2)[1]
	bad := map[string]string{
		"":                                "no key",
		" , \n ":                          "no key",
		"ssh-ed25519":                     "key 1: not",
		rsa:                               "key 1: type must be",
		k1 + ", ecdsa-sha2-nistp256 AAAA": "key 2: type must be",
		"ssh-ed25519 !!!":                 "not base64",
		"ssh-ed25519 " + strings.SplitN(k2, " ", 2)[1]:                     "does not match its type",
		sshKey("ssh-ed25519", keyBytes(1)[:31], ""):                        "not an Ed25519 key",
		sshKey("sk-ssh-ed25519@openssh.com", keyBytes(2), ""):              "no application",
		sshKey("sk-ssh-ed25519@openssh.com", keyBytes(2), "ssh:") + "AAAA": "not base64", // data after the padding
		k1 + "\n" + k1 + " again":                                          "key 2: listed twice",
	}
	for in, want := range bad {
		_, err := ParseReleaseSigners(in, true)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", in, err, want)
		}
		if err != nil && len(in) > 20 && strings.Contains(err.Error(), in[12:20]) {
			t.Errorf("%q: error carries key material: %v", in, err)
		}
	}
	// Trailing bytes after a well-formed key are refused.
	blob, _ := base64.StdEncoding.DecodeString(strings.SplitN(k1, " ", 2)[1])
	if _, err := ParseReleaseSigners("ssh-ed25519 "+base64.StdEncoding.EncodeToString(append(blob, 0)), true); err == nil ||
		!strings.Contains(err.Error(), "trailing bytes") {
		t.Fatalf("trailing bytes: %v", err)
	}
}

func TestReleaseVersionAndFingerprint(t *testing.T) {
	for _, v := range []string{"v0.86.0", "v1.2.3", "v10.20.300", "v0.0.0", "latest"} {
		if !ValidReleaseVersion(v) {
			t.Errorf("%q refused", v)
		}
	}
	for _, v := range []string{"", "0.86.0", "v0.86", "v0.86.0-rc1", "V0.86.0", "v0.86.0 ", "v01.2.3", "v1.02.3", "v1.2.03", "v00.1.0", "Latest", "LATEST", "latest ", " latest", "v-latest", "latest\n"} {
		if ValidReleaseVersion(v) {
			t.Errorf("%q accepted", v)
		}
	}
	k := sshKey("ssh-ed25519", ed25519.NewKeyFromSeed(vectorSeed()).Public().(ed25519.PublicKey), "")
	blob, _ := base64.StdEncoding.DecodeString(strings.SplitN(k, " ", 2)[1])
	sum := sha256.Sum256(blob)
	if fp := SignerFingerprint(k); fp != "SHA256:"+base64.RawStdEncoding.EncodeToString(sum[:]) || strings.HasSuffix(fp, "=") {
		t.Fatalf("fingerprint %s", fp)
	}
}
