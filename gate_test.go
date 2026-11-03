package main

import (
	"strings"
	"testing"
)

// The table of docs/prd/2026-11-03-mysql-connector.md §2.6, one row a case.
func TestGateServesOnlyWhereThePRDSaysItMay(t *testing.T) {
	for _, tc := range []struct {
		name      string
		env       map[string]string
		policy    string
		serve     bool
		warn      bool
		mustSayIn string
	}{
		{"own, hosted", env("host", "1"), "refuse", true, false, ""},
		{"own, hosted, policy irrelevant", env("host", "1"), "allow-with-warning", true, false, ""},
		{"own, not hosted, refuse", env("", "1"), "refuse", false, false, "not sandboxed"},
		{"own, not hosted, no policy set", env("", "1"), "", false, false, "not sandboxed"},
		{"own, not hosted, allow-with-warning", env("", "1"), "allow-with-warning", true, true, ""},
		{"own, not hosted, an unknown policy", env("", "1"), "yolo", false, false, "not sandboxed"},
		{"borrowed or platform, hosted", env("host", ""), "allow-with-warning", false, false, "not your own run"},
		{"borrowed or platform, not hosted", env("", ""), "allow-with-warning", false, false, "not your own run"},
		{"an older bridge sets neither", env("", ""), "refuse", false, false, "not your own run"},
		{"a claim of an own run with a wrong value", env("host", "yes"), "refuse", false, false, "not your own run"},
		{"a wrong placement value", env("hosted", "1"), "refuse", false, false, "not sandboxed"},
	} {
		d := Decide(func(k string) string { return tc.env[k] }, tc.policy)
		if d.Serve != tc.serve || d.Warn != tc.warn {
			t.Errorf("%s: serve=%v warn=%v, want serve=%v warn=%v", tc.name, d.Serve, d.Warn, tc.serve, tc.warn)
		}
		if !d.Serve && !strings.Contains(d.Reason, tc.mustSayIn) {
			t.Errorf("%s: reason %q does not say %q", tc.name, d.Reason, tc.mustSayIn)
		}
		if d.Serve && d.Reason != "" {
			t.Errorf("%s: a served run has a refusal reason %q", tc.name, d.Reason)
		}
	}
}

// A borrowed or platform drive is refused whatever the policy: allow-with-warning
// is about the member's own unsandboxed run, never about whose agent it is.
func TestGateNeverServesSomeoneElsesRun(t *testing.T) {
	for _, policy := range []string{"", "refuse", "allow-with-warning", "anything"} {
		for _, placement := range []string{"", "host"} {
			if d := Decide(func(k string) string { return map[string]string{"BNBLOC_TOOL_PLACEMENT": placement}[k] }, policy); d.Serve {
				t.Errorf("placement=%q policy=%q served a run that is not the member's own", placement, policy)
			}
		}
	}
}

func env(placement, own string) map[string]string {
	return map[string]string{"BNBLOC_TOOL_PLACEMENT": placement, "BNBLOC_TOOL_OWN_RUN": own}
}
