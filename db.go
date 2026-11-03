package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

// The limits of one result and one statement.
// decision: docs/prd/2026-11-03-mysql-connector.md D7.
const (
	MaxRows        = 200
	MaxBytes       = 256 << 10
	DefaultTimeout = 30 * time.Second
	maxPoolPerHost = 2
)

type Limits struct {
	// Timeout is how long one statement runs before it is killed on the server.
	// Zero is DefaultTimeout. A SQL statement reports no progress, so this one
	// limit is a clock (D7).
	Timeout time.Duration
}

func (l Limits) timeout() time.Duration {
	if l.Timeout > 0 {
		return l.Timeout
	}
	return DefaultTimeout
}

// QueryKind says how a statement runs: a read in a read-only session, or a
// change the member allowed, in a read-write one.
type QueryKind int

const (
	QueryRead QueryKind = iota
	QueryChange
)

// Result is what comes back to the agent: never a password, never a DSN.
type Result struct {
	Columns   []string `json:"columns,omitempty"`
	Rows      [][]any  `json:"rows,omitempty"`
	Affected  int64    `json:"affected,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
	Cut       string   `json:"cut,omitempty"`
	Err       string   `json:"error,omitempty"`
}

type Runner struct{ lim Limits }

func NewRunner(l Limits) *Runner { return &Runner{lim: l} }

func (r *Runner) open(c Connection, password string) (*sql.DB, error) {
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd = c.User, password
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(strings.Trim(c.Host, "[]"), strconv.Itoa(c.Port))
	cfg.DBName = c.Database
	cfg.Timeout = 10 * time.Second
	cfg.ParseTime = false
	cfg.InterpolateParams = false
	cfg.AllowAllFiles = false
	cfg.AllowCleartextPasswords = false
	cfg.MultiStatements = false
	// The TLS settings travel in the config itself, not through the driver's
	// global registry: a registry entry per connection is never freed and its
	// counter is shared by every call (a data race, found by -race).
	cfg.TLS = &tls.Config{ServerName: strings.Trim(c.Host, "[]"), MinVersion: tls.VersionTLS12}
	if c.TLS == TLSSkip {
		cfg.TLS = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // chosen by the member, shown in red, listed (D8)
	}
	conn, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(conn)
	db.SetMaxOpenConns(maxPoolPerHost)
	db.SetMaxIdleConns(0)
	return db, nil
}

// Query runs one statement. A read runs in a READ ONLY transaction, so the
// server itself refuses a write the classifier missed. A statement past its
// time is killed on the server.
func (r *Runner) Query(ctx context.Context, c Connection, password, query string, kind QueryKind) Result {
	db, err := r.open(c, password)
	if err != nil {
		return Result{Err: describe(err, password)}
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(ctx, r.lim.timeout())
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		return Result{Err: describe(err, password)}
	}
	defer conn.Close()
	var id uint64
	_ = conn.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&id)

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			if id != 0 {
				r.kill(c, password, id)
			}
		case <-done:
		}
	}()

	opts := &sql.TxOptions{ReadOnly: kind == QueryRead}
	tx, err := conn.BeginTx(ctx, opts)
	if err != nil {
		return Result{Err: describe(err, password)}
	}
	defer tx.Rollback() //nolint:errcheck
	var out Result
	if kind == QueryRead {
		out = readRows(ctx, tx, query)
	} else {
		res, err := tx.ExecContext(ctx, query)
		if err != nil {
			return Result{Err: describe(err, password)}
		}
		n, _ := res.RowsAffected()
		out = Result{Affected: n}
		if err := tx.Commit(); err != nil {
			return Result{Err: describe(err, password)}
		}
	}
	if out.Err != "" && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		out.Err = fmt.Sprintf("the statement ran longer than %s and was stopped on the server; narrow it (a WHERE, a LIMIT, an index)", r.lim.timeout())
	}
	return out
}

func readRows(ctx context.Context, tx *sql.Tx, query string) Result {
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return Result{Err: describe(err, "")}
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return Result{Err: describe(err, "")}
	}
	out := Result{Columns: cols}
	size := 0
	for rows.Next() {
		raw := make([]sql.RawBytes, len(cols))
		ptrs := make([]any, len(cols))
		for i := range raw {
			ptrs[i] = &raw[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return Result{Err: describe(err, "")}
		}
		row := make([]any, len(cols))
		rowSize := 0
		for i, b := range raw {
			if b == nil {
				continue
			}
			row[i] = string(b)
			rowSize += len(b)
		}
		if len(out.Rows) >= MaxRows {
			out.Truncated = true
			out.Cut = fmt.Sprintf("showing the first %d rows; there are more. Add a WHERE or a LIMIT (and ORDER BY) to see the rest.", MaxRows)
			break
		}
		if size+rowSize > MaxBytes {
			out.Truncated = true
			out.Cut = fmt.Sprintf("showing the first %d rows, which is %d KiB, the most one answer carries; there are more. Select fewer columns or add a LIMIT.", len(out.Rows), MaxBytes>>10)
			break
		}
		size += rowSize
		out.Rows = append(out.Rows, row)
	}
	if err := rows.Err(); err != nil && !out.Truncated {
		return Result{Err: describe(err, "")}
	}
	return out
}

// kill stops a statement on the server from a second connection of its own:
// the one running it may be wedged, and a dropped client leaves it running.
func (r *Runner) kill(c Connection, password string, id uint64) {
	db, err := r.open(c, password)
	if err != nil {
		return
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = db.ExecContext(ctx, "KILL "+strconv.FormatUint(id, 10))
}

var tableNameRE = regexp.MustCompile(`^[A-Za-z0-9_$]{1,64}$`)

// Describe lists the tables of the connection's database, or the columns of
// one table. The table is a name, never SQL.
func (r *Runner) Describe(ctx context.Context, c Connection, password, table string) Result {
	db, err := r.open(c, password)
	if err != nil {
		return Result{Err: describe(err, password)}
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(ctx, r.lim.timeout())
	defer cancel()
	var rows *sql.Rows
	if table == "" {
		rows, err = db.QueryContext(ctx, "SELECT TABLE_NAME, TABLE_TYPE, TABLE_ROWS FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME LIMIT ?", MaxRows)
	} else {
		if !tableNameRE.MatchString(table) {
			return Result{Err: "a table name is letters, digits, '_' or '$'"}
		}
		rows, err = db.QueryContext(ctx, "SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION LIMIT ?", table, MaxRows)
	}
	if err != nil {
		return Result{Err: describe(err, password)}
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	out := Result{Columns: cols}
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return Result{Err: describe(err, password)}
		}
		row := make([]any, len(cols))
		for i, v := range vals {
			if v.Valid {
				row[i] = v.String
			}
		}
		out.Rows = append(out.Rows, row)
	}
	if table != "" && len(out.Rows) == 0 {
		return Result{Err: fmt.Sprintf("there is no table %q in this database", table)}
	}
	return out
}

// describe turns a driver or server error into a plain sentence by class. It
// never repeats the password, and never the DSN.
func describe(err error, password string) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	var me *mysql.MySQLError
	var ne net.Error
	var sentence string
	switch {
	case errors.As(err, &me):
		switch me.Number {
		case 1045, 1044:
			sentence = "the server refused the user or password (or the user may not use this database)"
			if me.Number == 1044 {
				sentence = "this user is not allowed to use that database"
			}
		case 1142, 1143, 1370:
			sentence = "this user has no permission for that (" + me.Message + ")"
		case 1146:
			sentence = "there is no such table (" + me.Message + ")"
		case 1049:
			sentence = "there is no such database (" + me.Message + ")"
		case 1064:
			sentence = "the SQL has a syntax error (" + me.Message + ")"
		case 1792:
			sentence = "the session is read-only, so this statement was refused by the server: " + me.Message
		case 3024, 1317:
			sentence = "the statement ran too long and was stopped"
		default:
			sentence = fmt.Sprintf("the server answered error %d: %s", me.Number, me.Message)
		}
	case strings.Contains(msg, "x509") || strings.Contains(msg, "certificate") || strings.Contains(msg, "tls:"):
		sentence = "the server's certificate could not be verified (TLS). If you trust this server, connect again with the certificate check turned off, on the confirmation page"
	case errors.As(err, &ne) || strings.Contains(msg, "connection refused") || strings.Contains(msg, "no such host") || strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "dial tcp"):
		sentence = "could not reach the server at that host and port"
	case errors.Is(err, context.DeadlineExceeded):
		sentence = "the statement ran too long and was stopped"
	case errors.Is(err, context.Canceled):
		sentence = "the call was cancelled"
	default:
		sentence = "the database call failed: " + msg
	}
	if password != "" {
		sentence = strings.ReplaceAll(sentence, password, "***")
	}
	return sentence
}
