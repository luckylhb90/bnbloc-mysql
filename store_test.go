package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func newStore(t *testing.T, key string) *Store {
	t.Helper()
	s, err := OpenStore(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func conn(alias string) Connection {
	return Connection{Alias: alias, Host: "db.example.com", Port: 3306, Database: "sales", User: "report", TLS: TLSVerify}
}

func TestStoreKeepsSeveralNamedConnections(t *testing.T) {
	s := newStore(t, "settings-a")
	for _, a := range []string{"prod-ro", "analytics", "staging"} {
		if err := s.Put(conn(a), "pw-"+a); err != nil {
			t.Fatal(err)
		}
	}
	list := s.List()
	if len(list) != 3 {
		t.Fatalf("listed %d, want 3", len(list))
	}
	for _, a := range []string{"prod-ro", "analytics", "staging"} {
		c, pw, ok := s.Get(a)
		if !ok || c.Alias != a || pw != "pw-"+a {
			t.Errorf("Get(%q) = %+v %q %v: the connection and its own password must come back", a, c, pw, ok)
		}
	}
}

// An alias is a key, matched exactly. A near-miss is not that connection, and
// nothing falls back to "the only one" (PRD D4).
func TestStoreGetIsByExactAlias(t *testing.T) {
	s := newStore(t, "k")
	_ = s.Put(conn("Prod"), "p1")
	for _, a := range []string{"prod", "PROD", " Prod", "Prod ", "", "pro"} {
		if _, _, ok := s.Get(a); ok {
			t.Errorf("Get(%q) found a connection: an alias is matched exactly, never folded or trimmed", a)
		}
	}
	if _, _, ok := s.Get("Prod"); !ok {
		t.Error("the exact alias was not found")
	}
}

func TestStoreListNeverCarriesAPassword(t *testing.T) {
	s := newStore(t, "k")
	_ = s.Put(conn("a"), "hunter2-secret")
	if raw := string(mustJSON(s.List())); strings.Contains(raw, "hunter2") {
		t.Fatalf("the listing carries the password: %s", raw)
	}
}

func TestStoreLimitsConnections(t *testing.T) {
	s := newStore(t, "k")
	for i := 0; i < MaxConnections; i++ {
		if err := s.Put(conn("c"+string(rune('a'+i))), "p"); err != nil {
			t.Fatalf("connection %d refused: %v", i+1, err)
		}
	}
	err := s.Put(conn("one-too-many"), "p")
	if err == nil || !strings.Contains(err.Error(), "16") {
		t.Fatalf("the 17th connection: %v, want a refusal naming the limit", err)
	}
	if err := s.Put(conn("ca"), "new-password"); err != nil {
		t.Fatalf("changing an existing connection counted as a new one: %v", err)
	}
	if _, pw, _ := s.Get("ca"); pw != "new-password" {
		t.Errorf("the changed password was not kept: %q", pw)
	}
}

func TestStoreRefusesBadAliasesAndFields(t *testing.T) {
	s := newStore(t, "k")
	for name, c := range map[string]Connection{
		"empty alias":        conn(""),
		"alias with a slash": conn("a/b"),
		"alias with dots":    conn(".."),
		"alias too long":     conn(strings.Repeat("a", 65)),
		"alias with a space": conn("a b"),
		"no host":            func() Connection { c := conn("x"); c.Host = ""; return c }(),
		"host with a path":   func() Connection { c := conn("x"); c.Host = "db/x"; return c }(),
		"port 0":             func() Connection { c := conn("x"); c.Port = 0; return c }(),
		"port too big":       func() Connection { c := conn("x"); c.Port = 70000; return c }(),
		"no user":            func() Connection { c := conn("x"); c.User = ""; return c }(),
		"unknown tls":        func() Connection { c := conn("x"); c.TLS = "maybe"; return c }(),
	} {
		if err := s.Put(c, "p"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(s.List()) != 0 {
		t.Errorf("a refused connection was stored: %+v", s.List())
	}
}

// The store is private: owner-only file, owner-only directory, written atomically.
func TestStoreFilesAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := t.TempDir()
	s, err := OpenStore(dir, "k")
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Put(conn("a"), "pw")
	var files int
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || p == dir {
			return err
		}
		files++
		want := os.FileMode(0o600)
		if info.IsDir() {
			want = 0o700
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s has mode %o, want %o", p, info.Mode().Perm(), want)
		}
		return nil
	})
	if files == 0 {
		t.Fatal("nothing was written")
	}
}

// D12: two accounts of one OS user have two settings files, so two stores.
func TestStoreIsKeyedBySettingsFile(t *testing.T) {
	root := t.TempDir()
	a, _ := OpenStore(root, "/state/host-tool-settings/mysql-aaaa.json")
	b, _ := OpenStore(root, "/state/host-tool-settings/mysql-bbbb.json")
	_ = a.Put(conn("only-in-a"), "p")
	if _, _, ok := b.Get("only-in-a"); ok {
		t.Fatal("one account's connection is visible to another's store")
	}
	again, _ := OpenStore(root, "/state/host-tool-settings/mysql-aaaa.json")
	if _, _, ok := again.Get("only-in-a"); !ok {
		t.Fatal("the same settings file did not reopen the same store")
	}
}

func TestOpenStoreWithoutAKeyRefuses(t *testing.T) {
	if _, err := OpenStore(t.TempDir(), ""); err == nil {
		t.Fatal("a store with no account key opened: it would be shared by every account of this OS user")
	}
	if _, err := OpenStore("", "k"); err == nil {
		t.Fatal("a store with no directory opened")
	}
}

func TestStoreRemove(t *testing.T) {
	s := newStore(t, "k")
	_ = s.Put(conn("a"), "pw")
	if err := s.Remove("a"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.Get("a"); ok {
		t.Fatal("a removed connection is still there")
	}
	if err := s.Remove("a"); err == nil {
		t.Fatal("removing a connection that is gone said nothing")
	}
	reopened, _ := OpenStore(s.root, "k")
	if len(reopened.List()) != 0 {
		t.Fatal("the removal was not kept")
	}
	raw, _ := os.ReadFile(filepath.Join(s.dir, storeFile))
	if strings.Contains(string(raw), "pw") {
		t.Fatalf("the removed password is still in the file: %s", raw)
	}
}

func TestStoreSurvivesARestartAndRefusesACorruptFile(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenStore(dir, "k")
	_ = s.Put(conn("a"), "pw")
	again, err := OpenStore(dir, "k")
	if err != nil {
		t.Fatal(err)
	}
	if _, pw, ok := again.Get("a"); !ok || pw != "pw" {
		t.Fatal("the connection did not survive a restart")
	}
	if err := os.WriteFile(filepath.Join(s.dir, storeFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir, "k"); err == nil {
		t.Fatal("a corrupt store opened as an empty one: the member's connections would be silently overwritten")
	}
}
