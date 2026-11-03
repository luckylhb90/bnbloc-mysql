# bnbloc-mysql

**A [bnbloc](https://github.com/luckylhb90/bnbloc) agent queries the MySQL databases you connect, as you.**

An installable MCP tool component (`bnbloc.mcp.package/v1`, runtime `stdio`,
placement `host`). You keep any number of named connections (`prod-ro`,
`analytics`). Your agent names one by its alias and runs SQL: a read runs at
once; anything that changes data waits for your click, on your own computer.

| Tool | What |
|---|---|
| `mysql_connections {action}` | `list`, `add`, `remove`, `test`. `add` takes only non-secret fields (alias, host, port, database, user, tls). |
| `mysql_describe {alias, table?}` | the tables of the database, or one table's columns |
| `mysql_query {alias, sql, request?}` | one statement. A read returns at most 200 rows and 256 KiB, and says when it cut. Anything else is held for you. |

## How a connection is made, without the password passing through chat

1. In a room you tell your agent: "connect my MySQL, alias `analytics`, host
   `db.example.com`, database `sales`, user `report`".
2. The agent calls `mysql_connections add` with those fields. The tool opens a
   confirmation page **on your computer** (a one-time file the tool asks your
   system to open, not an address the agent is given). You type the password
   there. It is stored on your computer only.
3. The agent is told only that you were asked, then tests the connection.

The same page is where you **Allow** or **Deny** a change. It shows the exact
statement; an Allow is for that alias and that statement, it runs once, and it
expires after 5 minutes.

## What it will and will not do

- **Reads** (`SELECT`, `SHOW`, `DESCRIBE`, `EXPLAIN`, `WITH ... SELECT`) run at
  once, in a read-only transaction. The server itself refuses a write that
  slipped past the classifier.
- **Everything else is a change** and is held: the classifier is an allowlist, so
  a statement it cannot place is a change. More than one statement in a call is
  refused, not held. `SELECT ... INTO OUTFILE`, `FOR UPDATE`, `SLEEP()`,
  `LOAD_FILE()` and executable comments (`/*! ... */`) are not reads.
- Every call names its alias, even with one connection. An alias is matched
  exactly: nothing is folded, trimmed or guessed.
- A statement that runs longer than 30 s is killed on the server, not just
  abandoned. At most 16 connections per member.
- TLS verifies the server certificate by default. A connection you trust but
  cannot verify (a self-signed server) is saved as "no verification" only on the
  confirmation page, shown in red.
- Use a **read-only database user** for production. The connector is a second
  line, not the first.

## Where it runs, and when it refuses

The bridge tells a host-run tool where it runs (`BNBLOC_TOOL_PLACEMENT=host`)
and whether the run is yours (`BNBLOC_TOOL_OWN_RUN=1`). This tool serves only
your own run, and by default only when it is hosted, which means your agent is
sandboxed and cannot read this tool's directory.

| Run | Result |
|---|---|
| Yours, sandboxed | Serves |
| Yours, not sandboxed | Refuses (default). With the organization setting **When the agent is not sandboxed = allow-with-warning**, serves and warns once |
| A borrowed or platform agent | Always refuses |
| A bnbloc that does not say | Refuses |

**Be clear about what this is.** The two variables tell an honest tool where it
runs; they are not a boundary. An agent that can run this binary can set them.
What keeps a hostile agent away from your saved passwords is the sandbox and the
read-deny on this tool's private directory (`privatePaths`), which the platform
builds for macOS; the Linux deny is not built yet. Where neither holds, the
agent can read the file as you whatever this tool refuses.

## Install into bnbloc

As a bnbloc super-admin:

```sh
bnbloc cores publish-mcp --gateway https://<gateway> --package package.json \
  --binary darwin-arm64=dist/bnbloc-mysql-darwin-arm64 --binary darwin-amd64=dist/bnbloc-mysql-darwin-amd64 \
  --binary linux-amd64=dist/bnbloc-mysql-linux-amd64 --binary windows-amd64=dist/bnbloc-mysql-windows-amd64.exe \
  --rollout optin
```

An organization admin then sets **When the agent is not sandboxed** in
Organization → Component settings. It needs a bnbloc whose bridge sets the two
variables; an older one makes this tool refuse, visibly.

## Build and test

```sh
go test ./...                       # the classifier, gate, store and page need no database
BNBLOC_TEST_MYSQL_ADDR=127.0.0.1:3306 go test ./...   # the database tests, against testdata/seed.sql
go build -o bnbloc-mysql .
```

The database tests need a real MySQL 8 (or MariaDB) with the users and rows of
`testdata/seed.sql`, and skip without one: a fake would accept what a server
refuses, which is what a read-only session, `KILL QUERY` and a privilege are
for. Where the connections are kept: `<user config dir>/bnbloc-mysql/<hash of
your account's settings file>/connections.json` (0600), so two accounts on one
computer never see each other's.

## License

[Apache License 2.0](LICENSE).
