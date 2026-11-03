package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// serveStdio runs the JSON-RPC loop over in-memory pipes: one request a line.
func TestServeAnswersOneLinePerRequestAndIgnoresNotifications(t *testing.T) {
	r := newRig(t, ownHosted(), "refuse")
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n" +
		`{"jsonrpc":"2.0","id":3,"method":"nope"}` + "\n")
	var out bytes.Buffer
	if err := Serve(context.Background(), r.srv, in, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d answers for 3 requests and 1 notification:\n%s", len(lines), out.String())
	}
	var last struct {
		ID    int `json:"id"`
		Error *struct{ Code int }
	}
	if err := json.Unmarshal([]byte(lines[2]), &last); err != nil || last.ID != 3 || last.Error == nil || last.Error.Code != -32601 {
		t.Fatalf("an unknown method: %s", lines[2])
	}
}

// stateRoot is where connections live. It must be inside the user's config
// directory under the name package.json declares as privatePaths, because that
// is the path the platform read-denies to a confined agent.
func TestStateRootIsTheDeclaredPrivatePath(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("HOME", cfg)
	t.Setenv("BNBLOC_MYSQL_STATE_DIR", "")
	got, err := stateRoot(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	userCfg, _ := os.UserConfigDir()
	if got != filepath.Join(userCfg, PrivatePath) {
		t.Fatalf("state root = %s, want %s", got, filepath.Join(userCfg, PrivatePath))
	}
	if got, _ := stateRoot(func(k string) string {
		if k == "BNBLOC_MYSQL_STATE_DIR" {
			return "/override"
		}
		return ""
	}); got != "/override" {
		t.Fatalf("the override was ignored: %s", got)
	}
}

// The declared private path and the manifest must agree, or the platform denies
// the agent a directory this tool does not use.
func TestPackageJSONDeclaresWhereTheStoreLives(t *testing.T) {
	raw, err := os.ReadFile("package.json")
	if err != nil {
		t.Fatal(err)
	}
	var pkg struct {
		MCP struct {
			Stdio struct {
				Placement    string   `json:"placement"`
				PrivatePaths []string `json:"privatePaths"`
			} `json:"stdio"`
		} `json:"mcp"`
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatal(err)
	}
	if pkg.MCP.Stdio.Placement != "host" {
		t.Errorf("placement = %q: this tool must run as a host process", pkg.MCP.Stdio.Placement)
	}
	if len(pkg.MCP.Stdio.PrivatePaths) != 1 || pkg.MCP.Stdio.PrivatePaths[0] != PrivatePath {
		t.Errorf("privatePaths = %v, want [%s]", pkg.MCP.Stdio.PrivatePaths, PrivatePath)
	}
}

// The binary itself, started the way the bridge starts it: a refusal when it is
// not hosted, and no secret on its output.
func TestTheBinaryRefusesWhenItIsNotTold(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "bnbloc-mysql")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	for name, env := range map[string][]string{
		"neither variable":    {},
		"hosted, not own run": {"BNBLOC_TOOL_PLACEMENT=host"},
		"own run, unhosted":   {"BNBLOC_TOOL_OWN_RUN=1"},
	} {
		cmd := exec.Command(bin)
		cmd.Env = append([]string{"HOME=" + t.TempDir(), "BNBLOC_COMPONENT_SETTINGS_FILE=" + filepath.Join(t.TempDir(), "s.json")}, env...)
		cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mysql_query","arguments":{"alias":"a","sql":"SELECT 1"}}}` + "\n")
		done := make(chan string, 1)
		go func() {
			out, _ := cmd.CombinedOutput()
			done <- string(out)
		}()
		select {
		case out := <-done:
			if !strings.Contains(out, `"isError":true`) {
				t.Errorf("%s: served, or did not say it refused: %s", name, out)
			}
		case <-time.After(20 * time.Second):
			_ = cmd.Process.Kill()
			t.Fatalf("%s: the binary did not exit when its input closed", name)
		}
	}
}

func TestTheBinaryWithoutAnAccountKeyRefusesToServe(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "bnbloc-mysql")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cmd := exec.Command(bin)
	cmd.Env = []string{"HOME=" + t.TempDir(), "BNBLOC_TOOL_PLACEMENT=host", "BNBLOC_TOOL_OWN_RUN=1"}
	cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("started with no BNBLOC_COMPONENT_SETTINGS_FILE: it would use a store shared by every account.\n%s", out)
	}
	if !strings.Contains(string(out), "account") {
		t.Errorf("the refusal does not say why: %s", out)
	}
	_ = bufio.NewReader
}
