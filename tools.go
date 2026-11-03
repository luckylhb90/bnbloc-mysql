package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ServerConfig is everything the tool server needs from its surroundings.
type ServerConfig struct {
	Env     func(string) string
	Policy  string
	Store   *Store
	Pending *Pending
	Runner  *Runner
	// Open asks the operating system to show a file to the member. The agent
	// is never told where the file is.
	Open func(file string) error
}

// Server answers the MCP methods. One tool per domain, with an action where a
// domain has several (a tool's size in tools/list is paid every turn).
type Server struct {
	cfg ServerConfig
	dec Decision

	mu     sync.Mutex
	warned bool
	// asked remembers which request an agent's change belongs to, so an Allow
	// for one statement on one alias can never be used for another: the request
	// id is the key, never a search for "the pending change" (AGENTS.md, refer to
	// a thing by its key).
	asked map[string]askedChange
}

type askedChange struct{ alias, sql string }

func NewServer(cfg ServerConfig) *Server {
	return &Server{cfg: cfg, dec: Decide(cfg.Env, cfg.Policy), asked: map[string]askedChange{}}
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var toolList = []any{
	map[string]any{
		"name":        "mysql_connections",
		"description": "The member's saved MySQL connections. action: list, add, remove, test. add takes only non-secret fields (alias, host, port, database, user, tls); the member types the password on their own computer. Every connection is named by its alias.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
			"action":   map[string]any{"type": "string", "enum": []string{"list", "add", "remove", "test"}},
			"alias":    map[string]any{"type": "string"},
			"host":     map[string]any{"type": "string"},
			"port":     map[string]any{"type": "integer"},
			"database": map[string]any{"type": "string"},
			"user":     map[string]any{"type": "string"},
			"tls":      map[string]any{"type": "string", "enum": []string{TLSVerify, TLSSkip}},
		}, "required": []string{"action"}},
	},
	map[string]any{
		"name":        "mysql_describe",
		"description": "Tables of a connection's database, or the columns of one table.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
			"alias": map[string]any{"type": "string"}, "table": map[string]any{"type": "string"},
		}, "required": []string{"alias"}},
	},
	map[string]any{
		"name":        "mysql_query",
		"description": "Run one SQL statement on a connection, named by alias. A read runs at once (at most 200 rows, 256 KiB). Anything else is held until the member allows that exact statement on their own computer; then call again with the same alias, sql and request.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
			"alias": map[string]any{"type": "string"}, "sql": map[string]any{"type": "string"}, "request": map[string]any{"type": "string"},
		}, "required": []string{"alias", "sql"}},
	},
}

func (s *Server) Dispatch(ctx context.Context, method string, params json.RawMessage) (any, *rpcError) {
	switch method {
	case "initialize":
		return map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "bnbloc-mysql", "version": "1"},
		}, nil
	case "notifications/initialized", "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": toolList}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(params, &p); err != nil || p.Name == "" {
			return nil, &rpcError{Code: -32602, Message: "tools/call needs a tool name"}
		}
		if len(p.Arguments) == 0 || string(p.Arguments) == "null" {
			p.Arguments = json.RawMessage(`{}`)
		}
		if !s.dec.Serve {
			return textResult(s.dec.Reason, true), nil
		}
		switch p.Name {
		case "mysql_connections":
			return s.connections(ctx, p.Arguments), nil
		case "mysql_describe":
			return s.describeTool(ctx, p.Arguments), nil
		case "mysql_query":
			return s.query(ctx, p.Arguments), nil
		}
		return nil, &rpcError{Code: -32602, Message: "unknown tool: " + p.Name}
	}
	return nil, &rpcError{Code: -32601, Message: "method not found: " + method}
}

func textResult(text string, isErr bool) map[string]any {
	out := map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}}
	if isErr {
		out["isError"] = true
	}
	return out
}

// answer is a successful result; the first one after an allow-with-warning
// decision carries the warning, once.
func (s *Server) answer(text string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dec.Warn && !s.warned {
		s.warned = true
		text = "WARNING: this session is not sandboxed, so your agent can read the file where your saved MySQL connections and passwords are kept: it is readable by the agent in this session. Your organization allows this; turning on the sandbox for your agent removes the risk.\n\n" + text
	}
	return textResult(text, false)
}

// resolve finds a connection by its exact alias. A missing one says so and lists
// the aliases that exist; nothing is guessed, even when there is only one.
func (s *Server) resolve(alias string) (Connection, string, *map[string]any) {
	c, pw, ok := s.cfg.Store.Get(alias)
	if ok {
		return c, pw, nil
	}
	var names []string
	for _, x := range s.cfg.Store.List() {
		names = append(names, x.Alias)
	}
	sort.Strings(names)
	msg := "name the connection by its alias with the alias argument."
	if alias != "" {
		msg = fmt.Sprintf("there is no connection called %q.", alias)
	}
	if len(names) > 0 {
		msg += " The aliases that exist: " + strings.Join(names, ", ") + "."
	} else {
		msg += " There are no connections yet; add one with mysql_connections."
	}
	r := textResult(msg, true)
	return Connection{}, "", &r
}

func (s *Server) connections(ctx context.Context, raw json.RawMessage) map[string]any {
	var in struct {
		Action   string `json:"action"`
		Alias    string `json:"alias"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Database string `json:"database"`
		User     string `json:"user"`
		TLS      string `json:"tls"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return textResult("the arguments are not valid: "+err.Error(), true)
	}
	switch in.Action {
	case "list":
		list := s.cfg.Store.List()
		if len(list) == 0 {
			return s.answer("No connections yet. Add one with action \"add\".")
		}
		return s.answer(string(mustIndent(list)))
	case "add":
		tlsMode := in.TLS
		if tlsMode == "" {
			tlsMode = TLSVerify
		}
		if in.Port == 0 {
			in.Port = 3306
		}
		c := Connection{Alias: in.Alias, Host: in.Host, Port: in.Port, Database: in.Database, User: in.User, TLS: tlsMode}
		if err := c.Validate(); err != nil {
			return textResult(err.Error(), true)
		}
		id, _, err := s.cfg.Pending.Ask(Action{Kind: ActPassword, Alias: c.Alias, Conn: c})
		if err != nil {
			return textResult("could not prepare the confirmation: "+err.Error(), true)
		}
		if err := s.cfg.Open(s.cfg.Pending.File(id)); err != nil {
			return textResult("could not open the confirmation on the member's computer: "+err.Error(), true)
		}
		return s.answer(s.cfg.Pending.ToAgent(id) + " They will type the password there; you never see it. Then use action \"test\".")
	case "remove":
		if err := s.cfg.Store.Remove(in.Alias); err != nil {
			return textResult(err.Error(), true)
		}
		return s.answer("Removed " + in.Alias + " and its saved password.")
	case "test":
		c, pw, miss := s.resolve(in.Alias)
		if miss != nil {
			return *miss
		}
		r := s.cfg.Runner.Query(ctx, c, pw, "SELECT VERSION() AS version, DATABASE() AS db", QueryRead)
		if r.Err != "" {
			return textResult(r.Err, true)
		}
		return s.answer("ok: " + string(mustIndent(r.Rows)))
	}
	return textResult(`action must be one of: list, add, remove, test`, true)
}

func (s *Server) describeTool(ctx context.Context, raw json.RawMessage) map[string]any {
	var in struct{ Alias, Table string }
	if err := json.Unmarshal(raw, &in); err != nil {
		return textResult("the arguments are not valid: "+err.Error(), true)
	}
	c, pw, miss := s.resolve(in.Alias)
	if miss != nil {
		return *miss
	}
	r := s.cfg.Runner.Describe(ctx, c, pw, in.Table)
	if r.Err != "" {
		return textResult(r.Err, true)
	}
	return s.answer(string(mustIndent(r)))
}

// query runs a read at once. Anything else is held for the member's click on
// that exact statement and runs once, only when called again with the request
// id it was given. decision: docs/prd/2026-11-03-mysql-connector.md D5, D9.
func (s *Server) query(ctx context.Context, raw json.RawMessage) map[string]any {
	var in struct {
		Alias   string `json:"alias"`
		SQL     string `json:"sql"`
		Request string `json:"request"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return textResult("the arguments are not valid: "+err.Error(), true)
	}
	c, pw, miss := s.resolve(in.Alias)
	if miss != nil {
		return *miss
	}
	verdict := Classify(in.SQL)
	if verdict.Class == Read {
		r := s.cfg.Runner.Query(ctx, c, pw, in.SQL, QueryRead)
		if r.Err != "" {
			return textResult(r.Err, true)
		}
		return s.answer(string(mustIndent(r)))
	}
	if verdict.Statements != 1 {
		return textResult("send one statement at a time ("+verdict.Why+").", true)
	}
	if in.Request == "" {
		return s.hold(c, in.Alias, in.SQL, verdict)
	}
	return s.runAllowed(ctx, c, pw, in.Alias, in.SQL, in.Request)
}

func (s *Server) hold(c Connection, alias, sql string, v Classification) map[string]any {
	id, _, err := s.cfg.Pending.Ask(Action{Kind: ActAllow, Alias: alias, SQL: sql})
	if err != nil {
		return textResult("could not prepare the confirmation: "+err.Error(), true)
	}
	if err := s.cfg.Open(s.cfg.Pending.File(id)); err != nil {
		return textResult("could not open the confirmation on the member's computer: "+err.Error(), true)
	}
	s.mu.Lock()
	s.asked[id] = askedChange{alias: alias, sql: sql}
	s.mu.Unlock()
	return s.answer("This changes data (" + v.Why + "), so it is held. " + s.cfg.Pending.ToAgent(id) + " When they have answered, call mysql_query again with the same alias, sql and request.")
}

func (s *Server) runAllowed(ctx context.Context, c Connection, pw, alias, sql, id string) map[string]any {
	s.mu.Lock()
	want, known := s.asked[id]
	s.mu.Unlock()
	if !known || want.alias != alias || want.sql != sql {
		return textResult("that request was not made for this alias and statement; a change is allowed one exact statement at a time. Ask again without a request id.", true)
	}
	state, found := s.cfg.Pending.State(id)
	switch {
	case !found:
		return textResult("there is no such request; ask again without a request id.", true)
	case state == StatePending:
		return s.answer("The member has not answered yet; still waiting. Check back with the same request id.")
	case state == StateDenied:
		return textResult("The member denied this change. Nothing was changed.", true)
	case state == StateExpired:
		return textResult("This request expired before the member answered. Nothing was changed; ask again if it is still needed.", true)
	}
	if !s.cfg.Pending.Consume(id, alias, sql) {
		return textResult("This allowance was already used (a change runs once). Ask again for another.", true)
	}
	r := s.cfg.Runner.Query(ctx, c, pw, sql, QueryChange)
	if r.Err != "" {
		return textResult(r.Err, true)
	}
	return s.answer(string(mustIndent(r)))
}

func mustIndent(v any) []byte {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []byte("{}")
	}
	return raw
}
