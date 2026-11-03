package main

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

// rig is the tool as the agent meets it: the whole server over its JSON-RPC
// door, a real database behind it, and the member's browser played by the test.
type rig struct {
	t       *testing.T
	srv     *Server
	pending *Pending
	store   *Store
	page    func(path string, form url.Values) (status int, body string)
	opened  []string
	clock   *fakeClock
}

func newRig(t *testing.T, env map[string]string, policy string) *rig {
	t.Helper()
	clock := &fakeClock{t: time.Now()}
	st := newStore(t, "settings-"+t.Name())
	p := NewPending(t.TempDir(), clock.now)
	r := &rig{t: t, pending: p, store: st, clock: clock}
	srv := NewServer(ServerConfig{
		Env: func(k string) string { return env[k] }, Policy: policy,
		Store: st, Pending: p, Runner: NewRunner(Limits{Timeout: 5 * time.Second}),
		Open: func(file string) error { r.opened = append(r.opened, file); return nil },
	})
	r.srv = srv
	httpSrv := serve(t, p, st)
	p.Base = httpSrv.URL
	r.page = func(path string, form url.Values) (int, string) {
		resp := post(t, httpSrv, path, form, "")
		return resp.StatusCode, readAll(resp)
	}
	return r
}

func ownHosted() map[string]string { return env("host", "1") }

// call is one tools/call, returning the text the agent reads and whether it is an error.
func (r *rig) call(name string, args map[string]any) (string, bool) {
	r.t.Helper()
	raw, _ := json.Marshal(args)
	res, rerr := r.srv.Dispatch(context.Background(), "tools/call", json.RawMessage(`{"name":"`+name+`","arguments":`+string(raw)+`}`))
	if rerr != nil {
		return rerr.Message, true
	}
	m := res.(map[string]any)
	text := m["content"].([]any)[0].(map[string]any)["text"].(string)
	isErr, _ := m["isError"].(bool)
	return text, isErr
}

// approve plays the member: opens the file the tool asked the OS to open, reads
// the address and token out of it as a browser would, and posts the answer.
func (r *rig) approve(file string, decision string, extra url.Values) (int, string) {
	r.t.Helper()
	raw := readFile(r.t, file)
	m := metaURLRE.FindStringSubmatch(raw)
	if m == nil {
		r.t.Fatalf("the page file has no address: %s", raw)
	}
	u, _ := url.Parse(unescape(m[1]))
	token := u.Fragment
	form := url.Values{"token": {token}, "decision": {decision}}
	for k, v := range extra {
		form[k] = v
	}
	return r.page(u.Path, form)
}

func TestToolsListIsFewAndNamedForTheDomain(t *testing.T) {
	r := newRig(t, ownHosted(), "refuse")
	res, rerr := r.srv.Dispatch(context.Background(), "tools/list", nil)
	if rerr != nil {
		t.Fatal(rerr)
	}
	tools := res.(map[string]any)["tools"].([]any)
	var names []string
	for _, x := range tools {
		names = append(names, x.(map[string]any)["name"].(string))
	}
	if strings.Join(names, ",") != "mysql_connections,mysql_describe,mysql_query" {
		t.Fatalf("tools = %v; a tool's size is paid every turn, so one per domain", names)
	}
	if size := len(mustJSON(res)); size > 4096 {
		t.Errorf("tools/list is %d bytes; keep it short", size)
	}
}

// The whole story of the PRD, as one flow: add through the page, read, a held
// change, Allow, deny, expiry, and a password that never reaches the agent.
func TestTheWholeFlow(t *testing.T) {
	h, port := testServer(t)
	r := newRig(t, ownHosted(), "refuse")
	var everythingTheAgentSaw strings.Builder
	saw := func(s string) string { everythingTheAgentSaw.WriteString(s + "\n"); return s }

	out, isErr := r.call("mysql_connections", map[string]any{"action": "add", "alias": "analytics", "host": h, "port": port, "database": "sales", "user": "writer", "tls": "skip-verify"})
	saw(out)
	if isErr || !strings.Contains(out, "asked") || len(r.opened) != 1 {
		t.Fatalf("add: err=%v opened=%d out=%q", isErr, len(r.opened), out)
	}
	if _, _, ok := r.store.Get("analytics"); ok {
		t.Fatal("the connection was saved before the member typed a password")
	}
	if status, body := r.approve(r.opened[0], "allow", url.Values{"password": {"writer-pw"}}); status != 200 {
		t.Fatalf("the member's page answered %d: %s", status, body)
	}

	out, _ = r.call("mysql_connections", map[string]any{"action": "list"})
	if !strings.Contains(saw(out), "analytics") || strings.Contains(out, "writer-pw") {
		t.Fatalf("list: %s", out)
	}
	if out, isErr = r.call("mysql_connections", map[string]any{"action": "test", "alias": "analytics"}); isErr || !strings.Contains(saw(out), "ok") {
		t.Fatalf("test: %v %s", isErr, out)
	}

	out, isErr = r.call("mysql_query", map[string]any{"alias": "analytics", "sql": "SELECT COUNT(*) AS n FROM orders"})
	if isErr || !strings.Contains(saw(out), `"3"`) {
		t.Fatalf("read: err=%v %s", isErr, out)
	}

	restoreOrders(t)
	stmt := "UPDATE orders SET note = 'held' WHERE id = 1"
	out, isErr = r.call("mysql_query", map[string]any{"alias": "analytics", "sql": stmt})
	saw(out)
	if isErr || !strings.Contains(out, "member was asked") || len(r.opened) != 2 {
		t.Fatalf("a change must be held for the member: err=%v opened=%d out=%q", isErr, len(r.opened), out)
	}
	if n := countWhere(t, r, "note = 'held'"); n != "0" {
		t.Fatalf("the change ran before the member allowed it: %s", n)
	}
	id := requestID(t, out)
	if again, _ := r.call("mysql_query", map[string]any{"alias": "analytics", "sql": stmt, "request": id}); !strings.Contains(saw(again), "still waiting") {
		t.Fatalf("asking again before the member answered: %q", again)
	}
	if n := countWhere(t, r, "note = 'held'"); n != "0" {
		t.Fatal("asking again ran the change")
	}

	if status, body := r.approve(r.opened[1], "allow", nil); status != 200 {
		t.Fatalf("allow: %d %s", status, body)
	}
	other, _ := r.call("mysql_query", map[string]any{"alias": "analytics", "sql": "UPDATE orders SET note = 'other' WHERE id = 2", "request": id})
	saw(other)
	if strings.Contains(other, "affected") || countWhere(t, r, "note = 'other'") != "0" {
		t.Fatalf("an Allow for one statement ran another: %s", other)
	}
	done, isErr := r.call("mysql_query", map[string]any{"alias": "analytics", "sql": stmt, "request": id})
	saw(done)
	if isErr || !strings.Contains(done, `"affected": 1`) || countWhere(t, r, "note = 'held'") != "1" {
		t.Fatalf("the allowed change did not run once: err=%v %s", isErr, done)
	}
	if replay, _ := r.call("mysql_query", map[string]any{"alias": "analytics", "sql": stmt, "request": id}); strings.Contains(replay, `"affected"`) {
		t.Fatalf("an Allow ran twice: %s", replay)
	}

	out, _ = r.call("mysql_query", map[string]any{"alias": "analytics", "sql": "DELETE FROM orders"})
	saw(out)
	r.approve(r.opened[len(r.opened)-1], "deny", nil)
	if res, _ := r.call("mysql_query", map[string]any{"alias": "analytics", "sql": "DELETE FROM orders", "request": requestID(t, out)}); !strings.Contains(saw(res), "denied") {
		t.Fatalf("a denied change: %q", res)
	}
	if n := countWhere(t, r, "1 = 1"); n != "3" {
		t.Fatalf("a denied DELETE removed rows: %s", n)
	}

	out, _ = r.call("mysql_query", map[string]any{"alias": "analytics", "sql": "DROP TABLE big"})
	saw(out)
	r.clock.advance(PendingTTL + time.Second)
	if res, _ := r.call("mysql_query", map[string]any{"alias": "analytics", "sql": "DROP TABLE big", "request": requestID(t, out)}); !strings.Contains(saw(res), "expired") {
		t.Fatalf("an expired change: %q", res)
	}

	for _, secret := range []string{"writer-pw", r.pending.Dir(), r.pending.Base} {
		if strings.Contains(everythingTheAgentSaw.String(), secret) {
			t.Fatalf("the agent was shown %q:\n%s", secret, everythingTheAgentSaw.String())
		}
	}
	for _, f := range r.opened {
		if strings.Contains(everythingTheAgentSaw.String(), f) {
			t.Fatalf("the agent was shown the page file %s", f)
		}
	}
}

// An Allow is one execution. The statement here is not idempotent, so a replay
// changes the data again and cannot hide behind "set it to the same value".
func TestAnAllowedChangeRunsExactlyOnceEvenWhenAskedAgain(t *testing.T) {
	h, port := testServer(t)
	r := newRig(t, ownHosted(), "refuse")
	_ = r.store.Put(Connection{Alias: "rw", Host: h, Port: port, Database: "sales", User: "writer", TLS: TLSSkip}, "writer-pw")
	restoreOrders(t)
	stmt := "UPDATE orders SET total = total + 1 WHERE id = 1"
	out, _ := r.call("mysql_query", map[string]any{"alias": "rw", "sql": stmt})
	id := requestID(t, out)
	if status, _ := r.approve(r.opened[0], "allow", nil); status != 200 {
		t.Fatalf("allow answered %d", status)
	}
	ran := 0
	for i := 0; i < 5; i++ {
		if res, _ := r.call("mysql_query", map[string]any{"alias": "rw", "sql": stmt, "request": id}); strings.Contains(res, `"affected"`) {
			ran++
		}
	}
	if ran != 1 {
		t.Fatalf("one Allow ran the statement %d times", ran)
	}
	if got := countWhere(t, r, "id = 1 AND total = 11.50"); got != "1" {
		t.Fatalf("total was incremented more or less than once (%s rows at 11.50)", got)
	}
}

// More than one statement is refused outright, not sent to the member as a
// change: the member is never asked to approve something the connector will not run.
func TestAMultiStatementChangeIsRefusedNotHeld(t *testing.T) {
	h, port := testServer(t)
	r := newRig(t, ownHosted(), "refuse")
	_ = r.store.Put(Connection{Alias: "rw", Host: h, Port: port, Database: "sales", User: "writer", TLS: TLSSkip}, "writer-pw")
	for _, sql := range []string{
		"UPDATE orders SET note='a' WHERE id=1; UPDATE orders SET note='b' WHERE id=2",
		"DELETE FROM orders; DROP TABLE big",
		"SELECT 1; DELETE FROM orders",
	} {
		out, isErr := r.call("mysql_query", map[string]any{"alias": "rw", "sql": sql})
		if !isErr || !strings.Contains(out, "one statement at a time") {
			t.Errorf("%q: err=%v out=%q", sql, isErr, out)
		}
	}
	if len(r.opened) != 0 {
		t.Fatalf("the member was asked to approve %d multi-statement requests", len(r.opened))
	}
}

// Several connections, and every call names its alias (PRD D4).
func TestAliasIsRequiredEvenWithOneConnection(t *testing.T) {
	h, port := testServer(t)
	r := newRig(t, ownHosted(), "refuse")
	_ = r.store.Put(Connection{Alias: "only", Host: h, Port: port, Database: "sales", User: "report", TLS: TLSSkip}, "report-pw")
	for name, args := range map[string]map[string]any{
		"no alias":     {"sql": "SELECT 1"},
		"empty alias":  {"alias": "", "sql": "SELECT 1"},
		"a near miss":  {"alias": "ONLY", "sql": "SELECT 1"},
		"unknown":      {"alias": "other", "sql": "SELECT 1"},
		"padded alias": {"alias": " only", "sql": "SELECT 1"},
	} {
		out, isErr := r.call("mysql_query", args)
		if !isErr || strings.Contains(out, `"1"`) {
			t.Errorf("%s: ran a query on a connection it was not told: %q", name, out)
		}
		if name != "no alias" && name != "empty alias" && !strings.Contains(out, "only") {
			t.Errorf("%s: the refusal should list the aliases that exist so the agent can ask properly: %q", name, out)
		}
	}
}

func TestTwoConnectionsAreNeverConfused(t *testing.T) {
	h, port := testServer(t)
	r := newRig(t, ownHosted(), "refuse")
	_ = r.store.Put(Connection{Alias: "ro", Host: h, Port: port, Database: "sales", User: "report", TLS: TLSSkip}, "report-pw")
	_ = r.store.Put(Connection{Alias: "rw", Host: h, Port: port, Database: "sales", User: "writer", TLS: TLSSkip}, "writer-pw")
	who := func(alias string) string {
		out, isErr := r.call("mysql_query", map[string]any{"alias": alias, "sql": "SELECT SUBSTRING_INDEX(CURRENT_USER(), '@', 1) AS u"})
		if isErr {
			t.Fatalf("%s: %s", alias, out)
		}
		return out
	}
	if out := who("ro"); !strings.Contains(out, "report") {
		t.Errorf("ro ran as: %s", out)
	}
	if out := who("rw"); !strings.Contains(out, "writer") {
		t.Errorf("rw ran as: %s", out)
	}
}

// A statement the classifier calls a change is held; so is one it cannot read.
func TestOnlyAPositiveReadRunsAtOnce(t *testing.T) {
	h, port := testServer(t)
	r := newRig(t, ownHosted(), "refuse")
	_ = r.store.Put(Connection{Alias: "rw", Host: h, Port: port, Database: "sales", User: "writer", TLS: TLSSkip}, "writer-pw")
	restoreOrders(t)
	for _, sql := range []string{"DELETE FROM orders", "SELECT 1; DELETE FROM orders", "SELECT * FROM orders INTO OUTFILE '/tmp/x'", "SELECT 1 /*!50000 ; DELETE FROM orders */", "garbage", ""} {
		before := len(r.opened)
		out, _ := r.call("mysql_query", map[string]any{"alias": "rw", "sql": sql})
		if strings.Contains(out, `"affected"`) || strings.Contains(out, `"rows"`) {
			t.Errorf("%q ran without the member: %s", sql, out)
		}
		if sql != "" && len(r.opened) == before && !strings.Contains(out, "one statement") && !strings.Contains(out, "could not") {
			t.Errorf("%q was neither held for the member nor refused: %s", sql, out)
		}
	}
	if n := countWhere(t, r, "1 = 1"); n != "3" {
		t.Fatalf("rows changed: %s", n)
	}
}

// --- the gate, through the door ---

func TestARefusedRunServesNothingAndSaysWhy(t *testing.T) {
	for name, tc := range map[string]struct {
		env    map[string]string
		policy string
		want   string
	}{
		"unsandboxed, default policy":  {env("", "1"), "", "not sandboxed"},
		"unsandboxed, refuse":          {env("", "1"), "refuse", "not sandboxed"},
		"borrowed":                     {env("host", ""), "allow-with-warning", "not your own run"},
		"an older bridge sets nothing": {env("", ""), "allow-with-warning", "not your own run"},
	} {
		r := newRig(t, tc.env, tc.policy)
		for _, tool := range []string{"mysql_connections", "mysql_describe", "mysql_query"} {
			out, isErr := r.call(tool, map[string]any{"action": "list", "alias": "a", "sql": "SELECT 1"})
			if !isErr || !strings.Contains(out, tc.want) {
				t.Errorf("%s / %s: err=%v out=%q, want a refusal saying %q", name, tool, isErr, out, tc.want)
			}
		}
		if len(r.opened) != 0 {
			t.Errorf("%s: a refused run still opened a page", name)
		}
	}
}

func TestAllowWithWarningServesAndSaysWhatItCost(t *testing.T) {
	h, port := testServer(t)
	r := newRig(t, env("", "1"), "allow-with-warning")
	_ = r.store.Put(Connection{Alias: "ro", Host: h, Port: port, Database: "sales", User: "report", TLS: TLSSkip}, "report-pw")
	out, isErr := r.call("mysql_query", map[string]any{"alias": "ro", "sql": "SELECT 1"})
	if isErr || !strings.Contains(out, `"1"`) {
		t.Fatalf("an allowed unsandboxed run did not serve: %v %s", isErr, out)
	}
	if !strings.Contains(strings.ToLower(out), "warning") || !strings.Contains(out, "readable") {
		t.Errorf("the first answer must say the connection file is readable by the agent: %s", out)
	}
	out2, _ := r.call("mysql_query", map[string]any{"alias": "ro", "sql": "SELECT 2"})
	if strings.Contains(strings.ToLower(out2), "warning") {
		t.Errorf("the warning repeats on every answer: %s", out2)
	}
}

// --- helpers ---

func countWhere(t *testing.T, r *rig, where string) string {
	t.Helper()
	c, pw := liveConn(t, "report")
	res := run(t, c, pw, "SELECT COUNT(*) FROM orders WHERE "+where)
	if res.Err != "" {
		t.Fatal(res.Err)
	}
	return res.Rows[0][0].(string)
}
