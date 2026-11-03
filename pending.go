package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PendingTTL is how long a password page or an Allow waits for the member.
// decision: docs/prd/2026-11-03-mysql-connector.md D9.
const PendingTTL = 5 * time.Minute

type ActionKind int

const (
	// ActPassword asks the member to type a connection's password.
	ActPassword ActionKind = iota
	// ActAllow asks the member to allow one exact statement on one alias.
	ActAllow
)

type State int

const (
	StatePending State = iota
	StateAllowed
	StateDenied
	StateExpired
)

func (s State) String() string {
	return [...]string{"pending", "allowed", "denied", "expired"}[s]
}

// Action is something only the member may decide.
type Action struct {
	Kind  ActionKind
	Alias string
	// SQL is the exact statement an Allow is for.
	SQL string
	// Conn is the connection a password page saves, once it has its password.
	Conn Connection
}

type pendingEntry struct {
	act      Action
	token    string
	file     string
	asked    time.Time
	state    State
	consumed bool
	bound    [32]byte
}

// Pending holds the actions waiting for the member. Its page file lives in the
// tool's own private directory (the platform read-denies it to the agent) and
// carries the token; nothing the agent is told carries the token, the path or
// the directory (PRD §2.4).
type Pending struct {
	dir string
	now func() time.Time
	// Base is the address of the page, set once it listens.
	Base string

	mu  sync.Mutex
	all map[string]*pendingEntry
}

func NewPending(dir string, now func() time.Time) *Pending {
	return &Pending{dir: dir, now: now, Base: "http://127.0.0.1:0", all: map[string]*pendingEntry{}}
}

func (p *Pending) Dir() string { return p.dir }

func random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func bind(alias, sql string) [32]byte { return sha256.Sum256([]byte(alias + "\x00" + sql)) }

// Ask registers an action and writes its page file. It returns the action's id
// and its token; the token is for the file and the member's browser only.
func (p *Pending) Ask(a Action) (id, token string, err error) {
	id = hex.EncodeToString([]byte(random(12)))[:24]
	token = random(32)
	file := filepath.Join(p.dir, "pending-"+id+".html")
	url := p.Base + "/a/" + id + "#" + token
	page := fmt.Sprintf(`<!doctype html><meta charset="utf-8"><title>bnbloc MySQL</title>`+
		`<meta http-equiv="refresh" content="0;url=%s"><p>Opening <a href="%s">the confirmation page</a>.</p>`,
		html.EscapeString(url), html.EscapeString(url))
	if err := os.WriteFile(file, []byte(page), 0o600); err != nil {
		return "", "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.all[id] = &pendingEntry{act: a, token: token, file: file, asked: p.now(), bound: bind(a.Alias, a.SQL)}
	return id, token, nil
}

func (p *Pending) File(id string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.all[id]; e != nil {
		return e.file
	}
	return ""
}

func (p *Pending) expiredLocked(e *pendingEntry) bool {
	return !p.now().Before(e.asked.Add(PendingTTL))
}

// settleLocked turns a pending entry past its time into an expired one and
// removes its file.
func (p *Pending) settleLocked(e *pendingEntry) {
	if e.state == StatePending && p.expiredLocked(e) {
		e.state = StateExpired
		_ = os.Remove(e.file)
	}
}

// State is an action's state; false when there is no such action.
func (p *Pending) State(id string) (State, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.all[id]
	if e == nil {
		return 0, false
	}
	p.settleLocked(e)
	return e.state, true
}

// Peek is the state of a still-live pending action; ok is false once it is no
// longer waiting.
func (p *Pending) Peek(id string) (State, bool) {
	st, found := p.State(id)
	return st, found && st == StatePending
}

func (p *Pending) peekAction(id string) (Action, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.all[id]
	if e == nil {
		return Action{}, false
	}
	return e.act, true
}

// Verify checks a token against a live pending action without using it up.
func (p *Pending) Verify(id, token string) (Action, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.all[id]
	if e == nil {
		return Action{}, errors.New("there is no such request")
	}
	p.settleLocked(e)
	switch {
	case e.state == StateExpired:
		return Action{}, errors.New("this request expired; ask the agent to try again")
	case e.state != StatePending:
		return Action{}, errors.New("this request was already answered")
	case token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(e.token)) != 1:
		return Action{}, errors.New("this link is not valid")
	}
	return e.act, nil
}

// Resolve records the member's answer, once, with the action's own token.
func (p *Pending) Resolve(id, token string, allow bool) error {
	if _, err := p.Verify(id, token); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.all[id]
	if e.state != StatePending {
		return errors.New("this request was already answered")
	}
	e.state = StateDenied
	if allow {
		e.state = StateAllowed
	}
	_ = os.Remove(e.file)
	return nil
}

// allowedLocked says whether id was allowed for exactly this alias and
// statement and has not been used. Another alias, another statement, a changed
// byte: no.
func (p *Pending) allowedLocked(id, alias, sql string) *pendingEntry {
	e := p.all[id]
	if e == nil || e.act.Kind != ActAllow || e.state != StateAllowed || e.consumed || p.expiredLocked(e) {
		return nil
	}
	want := bind(alias, sql)
	if subtle.ConstantTimeCompare(e.bound[:], want[:]) != 1 {
		return nil
	}
	return e
}

// Allowed reports an unused Allow for exactly this alias and statement.
func (p *Pending) Allowed(id, alias, sql string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.allowedLocked(id, alias, sql) != nil
}

// Consume checks the Allow and uses it up in one step under one lock: a
// statement the member allowed runs once, however many callers ask at once.
func (p *Pending) Consume(id, alias, sql string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.allowedLocked(id, alias, sql)
	if e == nil {
		return false
	}
	e.consumed = true
	return true
}

// Sweep settles what has run out of time and forgets what is long finished.
func (p *Pending) Sweep() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, e := range p.all {
		p.settleLocked(e)
		if e.state != StatePending && p.now().After(e.asked.Add(2*PendingTTL)) {
			delete(p.all, id)
		}
	}
}

// ToAgent is all the agent learns of an action: that the member was asked.
// Never the token, the file or the directory.
func (p *Pending) ToAgent(id string) string {
	return fmt.Sprintf("The member was asked on their own computer (request %s). Nothing has happened yet; it expires in %d minutes. Check back with the same request id.", id, int(PendingTTL.Minutes()))
}
