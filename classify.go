package main

import (
	"strings"
)

// Class says what a statement does to the database, as far as the classifier
// can prove.
type Class int

const (
	// Change is everything that is not positively a read.
	Change Class = iota
	Read
)

func (c Class) String() string {
	if c == Read {
		return "read"
	}
	return "change"
}

// Classification is the verdict on one statement string. Why is a plain-words
// reason a member or an agent may be shown.
type Classification struct {
	Class      Class
	Statements int
	Why        string
}

// readStarts are the leading keywords a statement may have to be a read.
// An allowlist: a keyword not here is a change.
var readStarts = map[string]bool{
	"select": true, "show": true, "describe": true, "desc": true, "explain": true, "with": true,
}

// writeWords make a statement a change wherever they appear as a word outside
// a string, a quoted name or a comment. WITH may lead a data-changing
// statement, and a SELECT can carry a clause that writes or locks.
var writeWords = map[string]string{
	"insert": "writes rows", "update": "writes rows (or FOR UPDATE: takes row locks)", "delete": "deletes rows", "replace": "writes rows",
	"drop": "drops an object", "alter": "alters an object", "create": "creates an object", "truncate": "empties a table",
	"grant": "changes privileges", "revoke": "changes privileges", "call": "runs a stored procedure",
	"load": "loads data", "rename": "renames an object", "lock": "takes a lock", "unlock": "releases a lock",
	"analyze": "runs the statement (EXPLAIN ANALYZE)", "outfile": "writes a file on the server",
	"dumpfile": "writes a file on the server", "into": "stores the result outside the answer",
	"share": "takes a lock (FOR SHARE, LOCK IN SHARE MODE)", "handler": "opens a handler",
}

// effectFunctions are functions with a side effect, a cost nobody asked for, or
// a read of the server's own disk. A call to one makes the statement a change.
var effectFunctions = map[string]string{
	"get_lock": "takes a lock", "release_lock": "releases a lock", "release_all_locks": "releases locks",
	"is_free_lock": "inspects locks", "sleep": "waits on the server", "benchmark": "burns server time",
	"load_file": "reads a file on the server", "master_pos_wait": "waits on the server",
	"source_pos_wait": "waits on the server", "wait_for_executed_gtid_set": "waits on the server",
}

// Classify decides whether sql is a read. It reads the statement the way the
// server's lexer does for the three things that can hide a second statement or
// a clause: strings, quoted names and comments. Anything it cannot place (an
// unbalanced quote or comment, an executable comment, a null byte, no
// statement at all) is a change. decision: docs/prd/2026-11-03-mysql-connector.md D5.
func Classify(sql string) Classification {
	toks, why := lex(sql)
	if why != "" {
		return Classification{Class: Change, Why: why}
	}
	statements := splitStatements(toks)
	out := Classification{Statements: len(statements)}
	switch {
	case len(statements) == 0:
		out.Why = "no statement"
		return out
	case len(statements) > 1:
		out.Why = "more than one statement; send one at a time"
		return out
	}
	words := statements[0]
	first := words[0]
	showing := firstWord(words).lower == "show"
	if first.kind == tokPunct && first.text == "(" {
		first = firstWord(words)
	}
	if first.kind != tokWord || !readStarts[first.lower] {
		out.Why = "not a statement the connector knows to be a read"
		return out
	}
	for i, w := range words {
		if w.kind != tokWord {
			continue
		}
		if reason, bad := writeWords[w.lower]; bad && !isName(words, i) && !(showing && w.lower == "create") && !asColumn(words, i) {
			out.Why = "contains " + strings.ToUpper(w.text) + ": it " + reason
			return out
		}
		if reason, bad := effectFunctions[w.lower]; bad && i+1 < len(words) && words[i+1].kind == tokPunct && words[i+1].text == "(" {
			out.Why = "calls " + strings.ToUpper(w.text) + ": it " + reason
			return out
		}
	}
	out.Class = Read
	return out
}

// isName reports whether the word at i is used as a name and not as a
// keyword: after a dot (t.update), or before one (update.col). A quoted name
// is not a word token at all.
func isName(words []token, i int) bool {
	if i > 0 && words[i-1].kind == tokPunct && words[i-1].text == "." {
		return true
	}
	if i+1 < len(words) && words[i+1].kind == tokPunct && words[i+1].text == "." {
		return true
	}
	return false
}

// asColumn reports whether a clause word sits where a column or table name
// does: directly after SELECT or a comma or an open parenthesis, and directly
// before FROM, a comma, a closing parenthesis, AS, or the end. "SELECT outfile
// FROM t" names a column; "SELECT a FROM t INTO OUTFILE 'x'" does not, because
// the word that follows INTO OUTFILE is a string, not one of those.
// INTO is never a column: it is a reserved word, and MySQL requires it quoted.
func asColumn(words []token, i int) bool {
	switch words[i].lower {
	case "into", "update", "delete", "insert", "replace", "drop", "alter", "create", "truncate",
		"grant", "revoke", "call", "load", "rename", "lock", "unlock", "analyze", "handler":
		return false
	}
	prev, next := token{}, token{}
	if i > 0 {
		prev = words[i-1]
	}
	if i+1 < len(words) {
		next = words[i+1]
	}
	afterSelectList := prev.kind == tokPunct && (prev.text == "," || prev.text == "(") || (prev.kind == tokWord && (prev.lower == "select" || prev.lower == "distinct"))
	beforeEnd := i+1 == len(words) || (next.kind == tokWord && (next.lower == "from" || next.lower == "as")) || (next.kind == tokPunct && (next.text == "," || next.text == ")"))
	return afterSelectList && beforeEnd
}

func firstWord(words []token) token {
	for _, w := range words {
		if w.kind == tokWord {
			return w
		}
		if w.kind != tokPunct || w.text != "(" {
			return token{}
		}
	}
	return token{}
}

type tokKind int

const (
	tokWord tokKind = iota
	tokPunct
	tokString
	tokQuoted
	tokNumber
)

type token struct {
	kind  tokKind
	text  string
	lower string
}

// lex splits sql into tokens, dropping comments and keeping strings and quoted
// names opaque. The second result is a reason the statement cannot be read
// safely, or "".
func lex(sql string) ([]token, string) {
	var toks []token
	n := len(sql)
	for i := 0; i < n; {
		c := sql[i]
		switch {
		case c == 0:
			return nil, "contains a null byte"
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f':
			i++
		case c == '-' && i+1 < n && sql[i+1] == '-' && (i+2 >= n || isSpaceOrControl(sql[i+2])):
			for i < n && sql[i] != '\n' {
				i++
			}
		case c == '#':
			for i < n && sql[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && sql[i+1] == '*':
			if i+2 < n && sql[i+2] == '!' {
				return nil, "contains an executable comment (/*! ... */), which the server runs"
			}
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				return nil, "has a comment that never closes"
			}
			i += 2 + end + 2
		case c == '\'' || c == '"':
			j, ok, ambiguous := scanQuoted(sql, i, c, true)
			if ambiguous {
				return nil, "has a string whose end depends on the server's backslash mode (NO_BACKSLASH_ESCAPES); rewrite it without a backslash before a quote"
			}
			if !ok {
				return nil, "has a quote that never closes"
			}
			toks = append(toks, token{kind: tokString, text: sql[i:j]})
			i = j
		case c == '`':
			j, ok, _ := scanQuoted(sql, i, c, false)
			if !ok {
				return nil, "has a quoted name that never closes"
			}
			toks = append(toks, token{kind: tokQuoted, text: sql[i:j]})
			i = j
		case isWordByte(c):
			j := i
			for j < n && isWordByte(sql[j]) {
				j++
			}
			w := sql[i:j]
			kind := tokWord
			if c >= '0' && c <= '9' {
				kind = tokNumber
			}
			toks = append(toks, token{kind: kind, text: w, lower: strings.ToLower(w)})
			i = j
		default:
			toks = append(toks, token{kind: tokPunct, text: string(c)})
			i++
		}
	}
	return toks, ""
}

// scanQuoted returns the index after the quote that closes the one at i. A
// doubled quote is one quote. In a string, whether a backslash escapes the next
// byte depends on the server's sql_mode (NO_BACKSLASH_ESCAPES turns it off), and
// the connector does not know the mode of the server it is talking to. So a
// string is read both ways, and when the two readings end it in different places
// the statement is ambiguous: a tail one reading sees as string the other sees as
// code. The second result is false for an unbalanced quote; ambiguous reports the
// disagreement.
func scanQuoted(sql string, i int, q byte, backslash bool) (end int, ok, ambiguous bool) {
	withEscapes, okA := closeQuote(sql, i, q, true)
	if !backslash {
		return withEscapes, okA, false
	}
	without, okB := closeQuote(sql, i, q, false)
	if okA != okB || (okA && withEscapes != without) {
		return 0, false, true
	}
	return withEscapes, okA, false
}

func closeQuote(sql string, i int, q byte, escapes bool) (int, bool) {
	n := len(sql)
	for j := i + 1; j < n; j++ {
		switch {
		case escapes && sql[j] == '\\':
			j++
		case sql[j] == q:
			if j+1 < n && sql[j+1] == q {
				j++
				continue
			}
			return j + 1, true
		}
	}
	return 0, false
}

func isWordByte(c byte) bool {
	return c == '_' || c == '$' || c == '@' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isSpaceOrControl(c byte) bool { return c <= ' ' }

// splitStatements groups tokens by top-level semicolons. Empty statements
// (a trailing semicolon, ";;") are dropped, so "SELECT 1;" is one statement
// and "SELECT 1;;DROP TABLE t" is two.
func splitStatements(toks []token) [][]token {
	var out [][]token
	var cur []token
	for _, t := range toks {
		if t.kind == tokPunct && t.text == ";" {
			if len(cur) > 0 {
				out = append(out, cur)
				cur = nil
			}
			continue
		}
		cur = append(cur, t)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}
