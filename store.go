package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// MaxConnections is how many connections one member keeps.
// decision: docs/prd/2026-11-03-mysql-connector.md D7.
const MaxConnections = 16

const storeFile = "connections.json"

// TLS modes of a connection. Verify is the default; Skip is chosen only on the
// member's page and is listed wherever connections are (D8).
const (
	TLSVerify = "verify"
	TLSSkip   = "skip-verify"
)

var aliasRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// hostRE is a host name or address, nothing that could be a path or a DSN
// fragment: the host is the one field that decides where a password is sent.
var hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$|^\[[0-9A-Fa-f:.]+\]$`)

// Connection is what the agent may see of a connection: never the password.
type Connection struct {
	Alias    string `json:"alias"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	User     string `json:"user"`
	TLS      string `json:"tls"`
}

type stored struct {
	Connection
	Password string `json:"password"`
}

// Store is one account's connections, kept as one owner-only file under a
// directory only that account's settings file names (D12).
type Store struct {
	root string
	dir  string
	mu   sync.Mutex
	all  map[string]stored
}

// OpenStore opens (creating, owner-only) the store for the account whose
// settings file is accountKey, under root. An empty key or root refuses: a store
// with no account would be shared by every account of this OS user.
// decision: docs/prd/2026-11-03-mysql-connector.md D12.
func OpenStore(root, accountKey string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("no place to keep connections (no state directory)")
	}
	if strings.TrimSpace(accountKey) == "" {
		return nil, errors.New("this tool was not started with its account's settings file, so it cannot tell whose connections these are; it will not guess")
	}
	sum := sha256.Sum256([]byte(accountKey))
	dir := filepath.Join(root, hex.EncodeToString(sum[:6]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{root: root, dir: dir, all: map[string]stored{}}
	raw, err := os.ReadFile(filepath.Join(dir, storeFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, err
	}
	var list []stored
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("the saved connections cannot be read (%v); the file was left as it is, not replaced", err)
	}
	for _, c := range list {
		s.all[c.Alias] = c
	}
	return s, nil
}

// Validate is the one rule for a connection's fields.
func (c Connection) Validate() error {
	switch {
	case !aliasRE.MatchString(c.Alias) || c.Alias == "." || c.Alias == "..":
		return errors.New("an alias is 1 to 64 letters, digits, '.', '_' or '-', starting with a letter or digit")
	case !hostRE.MatchString(c.Host):
		return errors.New("the host must be a host name or an address")
	case c.Port < 1 || c.Port > 65535:
		return errors.New("the port must be 1 to 65535")
	case strings.TrimSpace(c.User) == "" || len(c.User) > 128:
		return errors.New("a user is required")
	case len(c.Database) > 128:
		return errors.New("the database name is too long")
	case c.TLS != TLSVerify && c.TLS != TLSSkip:
		return errors.New("tls must be " + TLSVerify + " or " + TLSSkip)
	}
	return nil
}

// Put saves a connection and its password, replacing one with the same alias.
func (s *Store) Put(c Connection, password string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.all[c.Alias]; !exists && len(s.all) >= MaxConnections {
		return fmt.Errorf("you already have %d connections, the most this connector keeps; remove one first", MaxConnections)
	}
	s.all[c.Alias] = stored{Connection: c, Password: password}
	return s.saveLocked()
}

// Get returns a connection by its exact alias. It never searches: no case
// folding, no trimming, and no fallback to the only connection there is.
func (s *Store) Get(alias string) (Connection, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.all[alias]
	return c.Connection, c.Password, ok
}

// List is every connection without its password, by alias.
func (s *Store) List() []Connection {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Connection, 0, len(s.all))
	for _, c := range s.all {
		out = append(out, c.Connection)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out
}

// Remove deletes a connection and its password.
func (s *Store) Remove(alias string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.all[alias]; !ok {
		return fmt.Errorf("there is no connection called %q", alias)
	}
	delete(s.all, alias)
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	list := make([]stored, 0, len(s.all))
	for _, c := range s.all {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Alias < list[j].Alias })
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.dir, storeFile), raw)
}

// writeAtomic writes through a temp file in the same directory and renames it,
// owner-only, so a crash never leaves half a store.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return raw
}
