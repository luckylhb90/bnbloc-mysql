package main

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These run against a real MySQL (BNBLOC_TEST_MYSQL_ADDR=host:port, with the
// users and data of testdata/seed.sql) and are skipped without one: a fake
// would accept what a server refuses and prove nothing about a read-only
// session, KILL QUERY or a privilege (docs/design-review.md lens 9).
func testServer(t *testing.T) (host string, port int) {
	t.Helper()
	addr := os.Getenv("BNBLOC_TEST_MYSQL_ADDR")
	if addr == "" {
		t.Skip("BNBLOC_TEST_MYSQL_ADDR is not set")
	}
	h, p, ok := strings.Cut(addr, ":")
	n, err := strconv.Atoi(p)
	if !ok || err != nil {
		t.Fatalf("BNBLOC_TEST_MYSQL_ADDR=%q is not host:port", addr)
	}
	return h, n
}

func liveConn(t *testing.T, user string) (Connection, string) {
	h, p := testServer(t)
	pw := map[string]string{"report": "report-pw", "writer": "writer-pw"}[user]
	return Connection{Alias: user, Host: h, Port: p, Database: "sales", User: user, TLS: TLSSkip}, pw
}

// restoreOrders puts the seed rows back when the test ends, pass or fail: a test
// that changes data, failing, must not hand the next one a different database.
func restoreOrders(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		c, pw := liveConn(t, "writer")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		r := NewRunner(Limits{})
		for _, q := range []string{
			"DELETE FROM orders",
			"INSERT INTO orders VALUES (1,'acme',10.50,'first'),(2,'globex',99.99,NULL),(3,'initech',5.00,'it''s fine')",
		} {
			if res := r.Query(ctx, c, pw, q, QueryChange); res.Err != "" {
				t.Errorf("could not restore the orders table: %s", res.Err)
			}
		}
	})
}

func run(t *testing.T, c Connection, pw, sql string) Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return NewRunner(Limits{}).Query(ctx, c, pw, sql, QueryRead)
}

func TestReadReturnsRowsAndColumns(t *testing.T) {
	c, pw := liveConn(t, "report")
	r := run(t, c, pw, "SELECT id, customer, total, note FROM orders ORDER BY id")
	if r.Err != "" {
		t.Fatal(r.Err)
	}
	if len(r.Rows) != 3 || len(r.Columns) != 4 || r.Columns[1] != "customer" {
		t.Fatalf("got columns=%v rows=%d", r.Columns, len(r.Rows))
	}
	if r.Rows[0][1] != "acme" || r.Rows[0][2] != "10.50" {
		t.Errorf("first row = %v", r.Rows[0])
	}
	if r.Rows[1][3] != nil {
		t.Errorf("a NULL came back as %#v, want nil: an agent must tell NULL from the text \"NULL\"", r.Rows[1][3])
	}
	if r.Rows[2][3] != "it's fine" {
		t.Errorf("a quote in a value: %#v", r.Rows[2][3])
	}
}

// The read session is read-only at the server, so a write that slipped past the
// classifier still fails (PRD pre-mortem 3). Run as a user that CAN write, so a
// privilege error cannot be what stops it.
func TestAReadSessionCannotWriteEvenAsAUserWhoMay(t *testing.T) {
	restoreOrders(t)
	c, pw := liveConn(t, "writer")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := NewRunner(Limits{}).Query(ctx, c, pw, "DELETE FROM orders", QueryRead)
	if r.Err == "" {
		t.Fatal("a DELETE ran in a read session")
	}
	if !strings.Contains(strings.ToLower(r.Err), "read-only") && !strings.Contains(strings.ToLower(r.Err), "read only") {
		t.Fatalf("it failed, but not because the session is read-only (a privilege or syntax error would hide a gap): %s", r.Err)
	}
	if n := run(t, c, pw, "SELECT COUNT(*) FROM orders"); n.Rows[0][0] != "3" {
		t.Fatalf("the rows changed: %v", n.Rows)
	}
}

func TestAChangeRunsOnlyWhenAskedToAsAChange(t *testing.T) {
	restoreOrders(t)
	c, pw := liveConn(t, "writer")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := NewRunner(Limits{}).Query(ctx, c, pw, "UPDATE orders SET note = 'edited' WHERE id = 3", QueryChange)
	if r.Err != "" || r.Affected != 1 {
		t.Fatalf("err=%q affected=%d", r.Err, r.Affected)
	}
	back := NewRunner(Limits{}).Query(ctx, c, pw, "UPDATE orders SET note = 'it''s fine' WHERE id = 3", QueryChange)
	if back.Err != "" {
		t.Fatal(back.Err)
	}
}

func TestRowsAreCutAndTheCutIsSaid(t *testing.T) {
	c, pw := liveConn(t, "report")
	r := run(t, c, pw, "SELECT n, pad FROM big ORDER BY n")
	if r.Err != "" {
		t.Fatal(r.Err)
	}
	if len(r.Rows) != MaxRows || !r.Truncated || r.Cut == "" {
		t.Fatalf("rows=%d truncated=%v cut=%q, want %d rows cut and said", len(r.Rows), r.Truncated, r.Cut, MaxRows)
	}
	if !strings.Contains(r.Cut, "200") || !strings.Contains(strings.ToLower(r.Cut), "limit") {
		t.Errorf("the cut does not say how to narrow it: %q", r.Cut)
	}
	if r.Rows[len(r.Rows)-1][0] != "200" {
		t.Errorf("the rows kept are not the first 200: last = %v", r.Rows[len(r.Rows)-1])
	}
}

func TestBytesAreCutAndTheCutIsSaid(t *testing.T) {
	c, pw := liveConn(t, "report")
	r := run(t, c, pw, "SELECT n, REPEAT(pad, 20) FROM big ORDER BY n")
	if r.Err != "" {
		t.Fatal(r.Err)
	}
	if !r.Truncated || !strings.Contains(r.Cut, "KiB") {
		t.Fatalf("a result of ~1.8 KB a row for 200 rows is 360 KB, over %d: truncated=%v cut=%q", MaxBytes, r.Truncated, r.Cut)
	}
	var size int
	for _, row := range r.Rows {
		for _, v := range row {
			if s, ok := v.(string); ok {
				size += len(s)
			}
		}
	}
	if size > MaxBytes {
		t.Errorf("kept %d bytes, over the %d cap", size, MaxBytes)
	}
}

// A statement that runs past its time is stopped ON THE SERVER, not just
// abandoned: a dropped client leaves a query running on the member's database.
func TestATimedOutStatementIsKilledOnTheServer(t *testing.T) {
	c, pw := liveConn(t, "report")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	start := time.Now()
	r := NewRunner(Limits{Timeout: 2 * time.Second}).Query(ctx, c, pw, "SELECT a.n FROM big a, big b, big c WHERE a.n + b.n + c.n = -1", QueryRead)
	if r.Err == "" || !strings.Contains(r.Err, "ran longer than") {
		t.Fatalf("err = %q, want a timeout that says so", r.Err)
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Fatalf("returned after %s", d)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if n := run(t, c, pw, "SELECT COUNT(*) FROM information_schema.processlist WHERE info LIKE '%a.n + b.n + c.n%' AND info NOT LIKE '%processlist%'"); n.Err == "" && n.Rows[0][0] == "0" {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("the statement is still running on the server after its timeout")
}

func TestErrorsAreSortedIntoClassesInPlainWords(t *testing.T) {
	h, p := testServer(t)
	for name, tc := range map[string]struct {
		c    Connection
		pw   string
		sql  string
		want string
	}{
		"wrong password": {Connection{Alias: "x", Host: h, Port: p, Database: "sales", User: "report", TLS: TLSSkip}, "nope", "SELECT 1", "password"},
		"unreachable":    {Connection{Alias: "x", Host: "127.0.0.1", Port: 1, Database: "sales", User: "report", TLS: TLSSkip}, "report-pw", "SELECT 1", "reach"},
		"no such table":  {Connection{Alias: "x", Host: h, Port: p, Database: "sales", User: "report", TLS: TLSSkip}, "report-pw", "SELECT * FROM nothere", "table"},
		"no privilege":   {Connection{Alias: "x", Host: h, Port: p, Database: "sales", User: "report", TLS: TLSSkip}, "report-pw", "SELECT * FROM mysql.user", "permission"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		r := NewRunner(Limits{}).Query(ctx, tc.c, tc.pw, tc.sql, QueryRead)
		cancel()
		if r.Err == "" || !strings.Contains(strings.ToLower(r.Err), tc.want) {
			t.Errorf("%s: %q does not say %q", name, r.Err, tc.want)
		}
		if strings.Contains(r.Err, tc.pw) && tc.pw != "" {
			t.Errorf("%s: the error carries the password: %q", name, r.Err)
		}
	}
}

// TLS is verified by default: a server whose certificate cannot be verified is
// refused, and the member is told how to proceed (D8).
func TestTLSVerificationIsOnByDefault(t *testing.T) {
	c, pw := liveConn(t, "report")
	c.TLS = TLSVerify
	r := run(t, c, pw, "SELECT 1")
	if r.Err == "" {
		t.Skip("this server's certificate verified; nothing to refuse")
	}
	if !strings.Contains(strings.ToLower(r.Err), "certificate") && !strings.Contains(strings.ToLower(r.Err), "tls") {
		t.Fatalf("a TLS failure is reported as %q", r.Err)
	}
}

func TestDescribeListsTablesAndColumns(t *testing.T) {
	c, pw := liveConn(t, "report")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tables := NewRunner(Limits{}).Describe(ctx, c, pw, "")
	if tables.Err != "" || !containsRow(tables.Rows, "orders") || !containsRow(tables.Rows, "big") {
		t.Fatalf("tables: %+v", tables)
	}
	cols := NewRunner(Limits{}).Describe(ctx, c, pw, "orders")
	if cols.Err != "" || !containsRow(cols.Rows, "customer") {
		t.Fatalf("columns: %+v", cols)
	}
	bad := NewRunner(Limits{}).Describe(ctx, c, pw, "orders; DROP TABLE orders")
	if bad.Err == "" {
		t.Fatal("a table name with SQL in it was accepted")
	}
}

func containsRow(rows [][]any, want string) bool {
	for _, r := range rows {
		for _, v := range r {
			if s, ok := v.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// The server runs one statement per call whatever the classifier says: a second
// statement is a syntax error at the server, so a classifier gap cannot become two.
func TestTwoStatementsInOneCallNeverBothRun(t *testing.T) {
	restoreOrders(t)
	c, pw := liveConn(t, "writer")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := NewRunner(Limits{}).Query(ctx, c, pw, "UPDATE orders SET note = 'x' WHERE id = 1; UPDATE orders SET note = 'y' WHERE id = 2", QueryChange)
	if r.Err == "" {
		t.Fatal("two statements ran in one call")
	}
	n := run(t, c, pw, "SELECT COUNT(*) FROM orders WHERE note IN ('x', 'y')")
	if n.Err != "" || n.Rows[0][0] != "0" {
		t.Fatalf("one of the two ran anyway: %+v", n)
	}
}

// Whatever the table name says, it is a value, never SQL: the name check is a
// second line behind a parameterised query, and each is tested on its own.
func TestADescribeNameIsOnlyEverAValue(t *testing.T) {
	restoreOrders(t)
	c, pw := liveConn(t, "writer")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, name := range []string{"orders; DROP TABLE orders", "orders' OR '1'='1", "orders`", "a b", "../orders"} {
		if r := NewRunner(Limits{}).Describe(ctx, c, pw, name); r.Err == "" {
			t.Errorf("Describe(%q) was accepted", name)
		}
	}
	if n := run(t, c, pw, "SELECT COUNT(*) FROM orders"); n.Rows[0][0] != "3" {
		t.Fatalf("a table name changed the data: %v", n.Rows)
	}
	if !tableNameRE.MatchString("orders") || tableNameRE.MatchString("orders; x") {
		t.Fatal("the name rule is wrong")
	}
}

// A connection saved as verified must be verified: the default is the strict
// one, and only the member's explicit choice turns it off.
func TestAVerifiedConnectionRefusesAServerItCannotVerify(t *testing.T) {
	c, pw := liveConn(t, "report")
	c.TLS = TLSVerify
	if r := run(t, c, pw, "SELECT 1"); r.Err == "" || !strings.Contains(r.Err, "certificate") {
		t.Fatalf("a verified connection to a self-signed server: %q", r.Err)
	}
	c.TLS = TLSSkip
	if r := run(t, c, pw, "SELECT 1"); r.Err != "" {
		t.Fatalf("the member's explicit skip-verify was not honoured: %q", r.Err)
	}
}
