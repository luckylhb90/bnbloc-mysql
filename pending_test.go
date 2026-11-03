package main

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newPending(t *testing.T) (*Pending, *fakeClock, string) {
	t.Helper()
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	dir := t.TempDir()
	return NewPending(dir, clock.now), clock, dir
}

func TestPendingExpiresAfterFiveMinutes(t *testing.T) {
	p, clock, _ := newPending(t)
	id, _, err := p.Ask(Action{Kind: ActAllow, Alias: "a", SQL: "DELETE FROM t"})
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(PendingTTL - time.Second)
	if _, ok := p.Peek(id); !ok {
		t.Fatal("expired a second early")
	}
	clock.advance(2 * time.Second)
	if st, ok := p.Peek(id); ok || st != StateExpired {
		t.Fatalf("after the TTL: state=%v ok=%v, want expired", st, ok)
	}
	if err := p.Resolve(id, "token-does-not-matter", true); err == nil {
		t.Fatal("an expired action could still be resolved")
	}
}

func TestPendingResolvesOnceWithItsOwnToken(t *testing.T) {
	p, _, _ := newPending(t)
	id, tok, _ := p.Ask(Action{Kind: ActAllow, Alias: "a", SQL: "DELETE FROM t"})
	if err := p.Resolve(id, "wrong", true); err == nil {
		t.Fatal("a wrong token resolved the action")
	}
	if err := p.Resolve(id, "", true); err == nil {
		t.Fatal("an empty token resolved the action")
	}
	if err := p.Resolve(id, tok, true); err != nil {
		t.Fatalf("the right token was refused: %v", err)
	}
	if err := p.Resolve(id, tok, true); err == nil {
		t.Fatal("an action resolved twice")
	}
	if st, _ := p.State(id); st != StateAllowed {
		t.Fatalf("state = %v, want allowed", st)
	}
}

// An empty token is never a token, even where the stored one could be empty too.
func TestPendingEmptyTokenIsNeverValid(t *testing.T) {
	p, _, _ := newPending(t)
	id, _, _ := p.Ask(Action{Kind: ActAllow, Alias: "a", SQL: "DELETE FROM t"})
	if _, err := p.Verify(id, ""); err == nil {
		t.Fatal("an empty token verified")
	}
	p.mu.Lock()
	p.all[id].token = ""
	p.mu.Unlock()
	if _, err := p.Verify(id, ""); err == nil {
		t.Fatal("an empty token matched an empty stored token")
	}
}

// Answering is final: the state an answer set is not overwritten by a later one.
func TestPendingAnswerIsFinal(t *testing.T) {
	p, _, _ := newPending(t)
	id, tok, _ := p.Ask(Action{Kind: ActAllow, Alias: "a", SQL: "DELETE FROM t"})
	if err := p.Resolve(id, tok, false); err != nil {
		t.Fatal(err)
	}
	if err := p.Resolve(id, tok, true); err == nil {
		t.Fatal("a denied action was allowed by a second answer")
	}
	if st, _ := p.State(id); st != StateDenied {
		t.Fatalf("state = %v after a refused second answer, want denied", st)
	}
	if _, err := p.Verify(id, tok); err == nil {
		t.Fatal("an answered action still verifies")
	}
}

// The allowance of one Allow is consumed by exactly one caller, also when many
// ask at once. The window between a check and a set is tiny, so the race is run
// many times: one run passing proves nothing (it survived a non-atomic Consume
// when it ran once).
func TestAllowIsConsumedByExactlyOneCaller(t *testing.T) {
	for round := 0; round < 300; round++ {
		p, _, _ := newPending(t)
		id, tok, _ := p.Ask(Action{Kind: ActAllow, Alias: "a", SQL: "DELETE FROM t"})
		_ = p.Resolve(id, tok, true)
		const callers = 32
		got := make(chan bool, callers)
		start := make(chan struct{})
		for i := 0; i < callers; i++ {
			go func() { <-start; got <- p.Consume(id, "a", "DELETE FROM t") }()
		}
		close(start)
		won := 0
		for i := 0; i < callers; i++ {
			if <-got {
				won++
			}
		}
		if won != 1 {
			t.Fatalf("round %d: %d callers consumed one Allow, want exactly 1", round, won)
		}
	}
}

// One token is one action: another action's token resolves nothing here.
func TestPendingTokensAreNotInterchangeable(t *testing.T) {
	p, _, _ := newPending(t)
	idA, tokA, _ := p.Ask(Action{Kind: ActAllow, Alias: "a", SQL: "DELETE FROM a"})
	idB, tokB, _ := p.Ask(Action{Kind: ActAllow, Alias: "b", SQL: "DELETE FROM b"})
	if err := p.Resolve(idB, tokA, true); err == nil {
		t.Fatal("A's token resolved B")
	}
	if err := p.Resolve(idA, tokB, true); err == nil {
		t.Fatal("B's token resolved A")
	}
	if tokA == tokB || idA == idB {
		t.Fatal("two actions share an id or a token")
	}
}

// An Allow is bound to (alias, exact statement). A second ask for the same
// statement is a second click (D9).
func TestAllowIsBoundToTheStatement(t *testing.T) {
	p, _, _ := newPending(t)
	id, tok, _ := p.Ask(Action{Kind: ActAllow, Alias: "a", SQL: "DELETE FROM t WHERE id = 1"})
	_ = p.Resolve(id, tok, true)
	if !p.Allowed(id, "a", "DELETE FROM t WHERE id = 1") {
		t.Fatal("the allowed statement was not allowed")
	}
	for name, c := range map[string][2]string{
		"another alias":     {"b", "DELETE FROM t WHERE id = 1"},
		"another statement": {"a", "DELETE FROM t WHERE id = 2"},
		"a trailing space":  {"a", "DELETE FROM t WHERE id = 1 "},
		"another case":      {"a", "delete from t where id = 1"},
	} {
		if p.Allowed(id, c[0], c[1]) {
			t.Errorf("%s: an Allow for one statement ran another", name)
		}
	}
	if !p.Consume(id, "a", "DELETE FROM t WHERE id = 1") {
		t.Fatal("the first use was refused")
	}
	if p.Consume(id, "a", "DELETE FROM t WHERE id = 1") {
		t.Fatal("an Allow ran twice")
	}
}

func TestADeniedActionRunsNothing(t *testing.T) {
	p, _, _ := newPending(t)
	id, tok, _ := p.Ask(Action{Kind: ActAllow, Alias: "a", SQL: "DROP TABLE t"})
	_ = p.Resolve(id, tok, false)
	if p.Allowed(id, "a", "DROP TABLE t") || p.Consume(id, "a", "DROP TABLE t") {
		t.Fatal("a denied action ran")
	}
	if st, _ := p.State(id); st != StateDenied {
		t.Fatalf("state = %v, want denied", st)
	}
}

// The page's file holds the form and the token; it is where the agent cannot
// read and it is gone once used or expired (PRD §2.4).
func TestPendingFileIsPrivateAndGoesAway(t *testing.T) {
	p, clock, dir := newPending(t)
	id, tok, _ := p.Ask(Action{Kind: ActPassword, Alias: "a"})
	path := p.File(id)
	if !strings.HasPrefix(path, dir) {
		t.Fatalf("the page file %q is outside the tool's private directory %q", path, dir)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("page file mode %o, want 600", info.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), tok) {
		t.Error("the page file does not carry the token the form posts back")
	}
	if err := p.Resolve(id, tok, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the page file outlived its use")
	}
	id2, _, _ := p.Ask(Action{Kind: ActPassword, Alias: "b"})
	path2 := p.File(id2)
	clock.advance(PendingTTL + time.Second)
	p.Sweep()
	if _, err := os.Stat(path2); !os.IsNotExist(err) {
		t.Error("an expired page file was not removed")
	}
	_ = filepath.Base(path)
}

func TestNothingAnswersToTheAgentCarriesTheTokenOrPath(t *testing.T) {
	p, _, _ := newPending(t)
	id, tok, _ := p.Ask(Action{Kind: ActPassword, Alias: "a"})
	p.Base = "http://127.0.0.1:41999"
	say := p.ToAgent(id)
	for _, secret := range []string{tok, p.File(id), p.Dir(), p.Base, "127.0.0.1", "/a/"} {
		if secret != "" && strings.Contains(say, secret) {
			t.Fatalf("what the agent is told carries %q: %s", secret, say)
		}
	}
	if !strings.Contains(say, "asked") {
		t.Errorf("the agent is not told the member was asked: %q", say)
	}
}

// --- the page ---

func serve(t *testing.T, p *Pending, st *Store) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(NewPage(p, st).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, srv *httptest.Server, path string, form url.Values, host string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if host != "" {
		req.Host = host
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestPagePasswordSavesTheConnectionAndNeverEchoesIt(t *testing.T) {
	p, _, _ := newPending(t)
	st := newStore(t, "k")
	srv := serve(t, p, st)
	id, tok, _ := p.Ask(Action{Kind: ActPassword, Alias: "analytics", Conn: conn("analytics")})
	resp := post(t, srv, "/a/"+id, url.Values{"token": {tok}, "password": {"s3cret-pw"}, "decision": {"allow"}}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body := readAll(resp)
	if strings.Contains(body, "s3cret-pw") {
		t.Fatalf("the page echoed the password: %s", body)
	}
	if c, pw, ok := st.Get("analytics"); !ok || pw != "s3cret-pw" || c.Host != "db.example.com" {
		t.Fatalf("the connection was not saved with its password: %+v %q %v", c, pw, ok)
	}
}

func TestPageRefusesAWrongTokenAndSavesNothing(t *testing.T) {
	p, _, _ := newPending(t)
	st := newStore(t, "k")
	srv := serve(t, p, st)
	id, _, _ := p.Ask(Action{Kind: ActPassword, Alias: "a", Conn: conn("a")})
	if resp := post(t, srv, "/a/"+id, url.Values{"token": {"guess"}, "password": {"x"}}, ""); resp.StatusCode == http.StatusOK {
		t.Fatal("a wrong token was accepted")
	}
	if len(st.List()) != 0 {
		t.Fatal("a refused post saved a connection")
	}
}

// A page served on a loopback port is reachable from a web page the member has
// open (DNS rebinding) or from another local program: it checks the Host it was
// asked for and refuses a cross-site post (Sec-Fetch-Site, Origin).
func TestPageRefusesForeignHostsAndCrossSitePosts(t *testing.T) {
	p, _, _ := newPending(t)
	st := newStore(t, "k")
	srv := serve(t, p, st)
	id, tok, _ := p.Ask(Action{Kind: ActAllow, Alias: "a", SQL: "DELETE FROM t"})
	form := url.Values{"token": {tok}, "decision": {"allow"}}
	if resp := post(t, srv, "/a/"+id, form, "evil.example.com"); resp.StatusCode == http.StatusOK {
		t.Fatal("a foreign Host header was served (DNS rebinding)")
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/a/"+id, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example.com")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode == http.StatusOK {
		t.Fatal("a cross-origin post was served")
	}
	resp.Body.Close()
	req2, _ := http.NewRequest(http.MethodPost, srv.URL+"/a/"+id, strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Sec-Fetch-Site", "cross-site")
	resp2, _ := http.DefaultClient.Do(req2)
	if resp2.StatusCode == http.StatusOK {
		t.Fatal("a cross-site fetch was served")
	}
	resp2.Body.Close()
	if st, _ := p.State(id); st != StatePending {
		t.Fatalf("a refused request changed the action to %v", st)
	}
}

func TestPageNeverServesTheFormOnGET(t *testing.T) {
	p, _, _ := newPending(t)
	srv := serve(t, p, newStore(t, "k"))
	id, tok, _ := p.Ask(Action{Kind: ActPassword, Alias: "a", Conn: conn("a")})
	resp, err := http.Get(srv.URL + "/a/" + id)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := readAll(resp)
	if strings.Contains(body, tok) {
		t.Fatal("a GET handed out the token: anything that can reach the port could then resolve the action")
	}
	field := regexp.MustCompile(`<input[^>]*name="token"[^>]*>`).FindString(body)
	if field == "" || strings.Contains(field, "value=") {
		t.Fatalf("the token field must be present and empty (the browser fills it from the fragment): %q", field)
	}
}

func TestPageSendsNoStoreAndFramingHeaders(t *testing.T) {
	p, _, _ := newPending(t)
	srv := serve(t, p, newStore(t, "k"))
	id, _, _ := p.Ask(Action{Kind: ActPassword, Alias: "a", Conn: conn("a")})
	resp, err := http.Get(srv.URL + "/a/" + id)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Frame-Options") != "DENY" ||
		!strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("headers: %v", resp.Header)
	}
}

func readAll(r *http.Response) string {
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			return b.String()
		}
	}
}

var metaURLRE = regexp.MustCompile(`content="0;url=([^"]+)"`)

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func unescape(s string) string { return html.UnescapeString(s) }

var requestRE = regexp.MustCompile(`request ([0-9a-f]{24})`)

func requestID(t *testing.T, s string) string {
	t.Helper()
	m := requestRE.FindStringSubmatch(s)
	if m == nil {
		t.Fatalf("no request id in %q", s)
	}
	return m[1]
}
