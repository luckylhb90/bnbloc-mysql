package main

import "strings"

// The names the bridge tells a host-run tool where it runs with
// (core/pkgmeta ToolPlacementEnv, ToolOwnRunEnv). They are spelled here, not
// imported: this tool must keep building against a platform that predates them,
// and then it sees neither and refuses, which is the point.
const (
	placementEnv = "BNBLOC_TOOL_PLACEMENT"
	ownRunEnv    = "BNBLOC_TOOL_OWN_RUN"
)

// The org-scope setting that says what to do in the member's own run when the
// tool is not hosted (docs/prd/2026-11-03-mysql-connector.md D2).
const (
	policyRefuse             = "refuse"
	policyAllowWithWarning   = "allow-with-warning"
	unsandboxedPolicyKey     = "unsandboxedPolicy"
	unsandboxedPolicyEnvName = "BNBLOC_MYSQL_UNSANDBOXED_POLICY"
)

// Decision is whether this process serves its agent at all.
type Decision struct {
	Serve bool
	// Warn: serve, and say in the first answer that the connection file is
	// readable by the agent in this session.
	Warn   bool
	Reason string
}

// Decide applies the table of PRD §2.6. getenv reads the process environment;
// policy is the organization's unsandboxedPolicy.
//
// What this is not: the two variables are not a boundary. An agent that can
// run this binary can set both itself. They make the default safe for an honest
// tool (an older bridge, a borrowed or platform drive and an unsandboxed run
// all refuse without effort); what keeps a hostile agent from the connection
// file is the sandbox and the read-deny on this tool's private paths.
// decision: docs/prd/2026-11-03-mysql-connector.md D2, D3, D6.
func Decide(getenv func(string) string, policy string) Decision {
	own := getenv(ownRunEnv) == "1"
	hosted := getenv(placementEnv) == "host"
	switch {
	case !own:
		return Decision{Reason: "this is not your own run (a borrowed or platform agent, or a bnbloc that does not say), so your databases are not lent to it"}
	case hosted:
		return Decision{Serve: true}
	case strings.TrimSpace(policy) == policyAllowWithWarning:
		return Decision{Serve: true, Warn: true}
	default:
		return Decision{Reason: "this session is not sandboxed, so the agent could read your saved connections; your organization's policy is to refuse. Turn on the sandbox for your agent, or ask an admin to change the MySQL connector's unsandboxed policy"}
	}
}
