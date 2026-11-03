package main

import "testing"

// Classification decides whether a statement runs at once or waits for the
// member (docs/prd/2026-11-03-mysql-connector.md §3, pre-mortem 3). It is an
// allowlist: only a statement it positively recognises as a read is a read.
// Everything else, and anything it cannot make sense of, is a change.
func TestClassifyReads(t *testing.T) {
	for _, sql := range []string{
		"SELECT 1",
		"select * from orders where id = 7",
		"  \n\tSELECT name FROM t LIMIT 5;",
		"SELECT a, b FROM t WHERE x IN (1,2,3) ORDER BY a",
		"SHOW TABLES",
		"show databases",
		"SHOW FULL COLUMNS FROM orders",
		"SHOW CREATE TABLE orders",
		"DESCRIBE orders",
		"DESC orders",
		"EXPLAIN SELECT * FROM orders",
		"/* why */ SELECT 1",
		"-- a note\nSELECT 1",
		"WITH recent AS (SELECT * FROM orders) SELECT * FROM recent",
		"SELECT ';' AS semi",
		"SELECT 'a;b' FROM t",
		"SELECT \"x;y\" FROM t",
		"SELECT `we;ird` FROM t",
		"SELECT 'it''s' FROM t",
		"SELECT 1 -- trailing;",
		"SELECT 1;  ",
		"(SELECT 1) UNION (SELECT 2)",
	} {
		if got := Classify(sql); got.Class != Read {
			t.Errorf("Classify(%q) = %v (%s), want a read", sql, got.Class, got.Why)
		}
	}
}

func TestClassifyChanges(t *testing.T) {
	for _, sql := range []string{
		"INSERT INTO t VALUES (1)",
		"update t set a = 1",
		"DELETE FROM t",
		"REPLACE INTO t VALUES (1)",
		"TRUNCATE TABLE t",
		"DROP TABLE t",
		"DROP DATABASE sales",
		"ALTER TABLE t ADD COLUMN c INT",
		"CREATE TABLE x (a INT)",
		"GRANT ALL ON *.* TO 'u'@'%'",
		"CALL purge_everything()",
		"SET GLOBAL read_only = 0",
		"SET @a = 1",
		"LOCK TABLES t WRITE",
		"RENAME TABLE a TO b",
		"LOAD DATA INFILE '/etc/passwd' INTO TABLE t",
		"KILL 12",
		"USE other",
		"START TRANSACTION",
		"COMMIT",
		"EXECUTE s",
		"PREPARE s FROM 'DELETE FROM t'",
		"HANDLER t OPEN",
		"DO SLEEP(10)",
		"",
		"   ",
		"-- nothing but a comment",
		"/* nothing */",
	} {
		if got := Classify(sql); got.Class != Change {
			t.Errorf("Classify(%q) = %v (%s), want a change", sql, got.Class, got.Why)
		}
	}
}

// The tricks: a statement written to look like a read, or to hide a second
// statement, a file write or a side effect. Each must not be a read.
func TestClassifyRefusesTricks(t *testing.T) {
	for name, sql := range map[string]string{
		"two statements":                    "SELECT 1; DROP TABLE t",
		"two statements, newline":           "SELECT 1;\nDELETE FROM t",
		"second after a comment":            "SELECT 1; /* x */ DELETE FROM t",
		"stacked after trailing semicolon":  "SELECT 1;;DROP TABLE t",
		"semicolon in a comment is not one": "SELECT 1 /* ; */; DROP TABLE t",
		"a write behind a comment opener":   "/* SELECT */ DELETE FROM t",
		"a write behind a line comment":     "-- SELECT\nDELETE FROM t",
		"mysql executable comment":          "SELECT 1 /*! ; DROP TABLE t */",
		"executable comment with version":   "SELECT 1 /*!50000 ; DELETE FROM t */",
		"executable comment leading":        "/*!50000 DELETE FROM t */",
		"executable comment, no semicolon":  "SELECT 1 /*!50000 INTO OUTFILE '/tmp/x' */",
		"executable comment, a procedure":   "SELECT 1 /*!80000 PROCEDURE ANALYSE() */",
		"executable comment, empty":         "SELECT 1 /*!50000 */",
		"executable comment, a subquery":    "SELECT * FROM t /*!50000 WHERE a = (SELECT 1) */",
		"executable comment hides a clause": "SELECT * FROM t /*!50000 FOR UPDATE */",
		"optimizer hint is not executable":  "SELECT /*+ MAX_EXECUTION_TIME(1) */ 1; DROP TABLE t",
		"into outfile":                      "SELECT * FROM t INTO OUTFILE '/tmp/x'",
		"into dumpfile":                     "SELECT * FROM t INTO DUMPFILE '/tmp/x'",
		"into outfile, odd case and space":  "SELECT * FROM t Into\n\tOutFile '/tmp/x'",
		"into a variable":                   "SELECT a INTO @v FROM t",
		"into a variable, comment between":  "SELECT a /* x */ INTO /* y */ @v FROM t",
		"for update lock":                   "SELECT * FROM t FOR UPDATE",
		"lock in share mode":                "SELECT * FROM t LOCK IN SHARE MODE",
		"for share":                         "SELECT * FROM t FOR SHARE",
		"get_lock side effect":              "SELECT GET_LOCK('a', 100)",
		"sleep":                             "SELECT SLEEP(3600)",
		"benchmark":                         "SELECT BENCHMARK(100000000, MD5('a'))",
		"load_file reads the server's disk": "SELECT LOAD_FILE('/etc/passwd')",
		"release_all_locks":                 "SELECT RELEASE_ALL_LOCKS()",
		"explain analyze runs the query":    "EXPLAIN ANALYZE SELECT * FROM t",
		"explain a write":                   "EXPLAIN DELETE FROM t",
		"with ... delete":                   "WITH x AS (SELECT 1) DELETE FROM t",
		"with ... insert":                   "WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x",
		"with ... update":                   "WITH x AS (SELECT 1) UPDATE t SET a = 1",
		"unbalanced quote hides a tail":     "SELECT 'a; DROP TABLE t",
		"unbalanced comment":                "SELECT 1 /* ; DROP TABLE t",
		"backslash escapes in a string":     "SELECT 'a\\'; DROP TABLE t; --'",
		"null byte":                         "SELECT 1\x00; DROP TABLE t",
		"select is not the first word":      "XSELECT 1",
		"keyword as a prefix of a name":     "SELECTED 1",
		"show with a write after":           "SHOW TABLES; DROP TABLE t",
		"describe then more":                "DESCRIBE t; DELETE FROM t",
	} {
		if got := Classify(sql); got.Class == Read {
			t.Errorf("%s: Classify(%q) = a read; it must not be", name, sql)
		}
	}
}

// What is a read must not be refused for being a name that looks like a trick.
func TestClassifyDoesNotMistakeNamesForTricks(t *testing.T) {
	for _, sql := range []string{
		"SELECT outfile FROM t",
		"SELECT * FROM sleeper",
		"SELECT `into` FROM t",
		"SELECT 'INTO OUTFILE' AS s",
		"SELECT 'for update' AS s",
		"SELECT updated_at, deleted FROM t",
		"SELECT * FROM `drop`",
		"SELECT 1 /*+ NO_INDEX(t) */",
	} {
		if got := Classify(sql); got.Class != Read {
			t.Errorf("Classify(%q) = %v (%s), want a read: the word is a name or a string, not the clause", sql, got.Class, got.Why)
		}
	}
}

func TestClassifyKnowsItsOwnLength(t *testing.T) {
	if got := Classify("SELECT 1"); got.Statements != 1 {
		t.Errorf("one statement counted as %d", got.Statements)
	}
	if got := Classify("SELECT 1; SELECT 2"); got.Statements != 2 || got.Class == Read {
		t.Errorf("two statements: counted %d, class %v; more than one is never a read", got.Statements, got.Class)
	}
}
