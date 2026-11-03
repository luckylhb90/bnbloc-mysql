// Command bnbloc-mysql is the MySQL MCP tool component
// (bnbloc.mcp.package/v1, runtime stdio, placement host;
// docs/prd/2026-11-03-mysql-connector.md in the bnbloc repository): a member's
// agent queries the databases that member connected, in their name. The agent
// never sees a password: the member types it on a page this process serves on
// their own computer, and the same page is where they allow a change.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// PrivatePath is the directory under the user's config directory this tool
// keeps its state in. package.json declares it as privatePaths, which is the
// path the platform read-denies to a confined agent.
const PrivatePath = "bnbloc-mysql"

const settingsFileEnv = "BNBLOC_COMPONENT_SETTINGS_FILE"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := runServer(ctx, os.Getenv, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "bnbloc-mysql:", err)
		os.Exit(1)
	}
}

func runServer(ctx context.Context, getenv func(string) string, in io.Reader, out io.Writer) error {
	root, err := stateRoot(getenv)
	if err != nil {
		return err
	}
	store, err := OpenStore(root, getenv(settingsFileEnv))
	if err != nil {
		return err
	}
	pending := NewPending(store.dir, time.Now)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	pending.Base = "http://" + ln.Addr().String()
	httpSrv := &http.Server{Handler: NewPage(pending, store).Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = httpSrv.Serve(ln) }()
	defer httpSrv.Close()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				pending.Sweep()
			case <-ctx.Done():
				return
			}
		}
	}()
	srv := NewServer(ServerConfig{
		Env: getenv, Policy: policyOf(getenv), Store: store, Pending: pending,
		Runner: NewRunner(Limits{}), Open: openFile,
	})
	return Serve(ctx, srv, in, out)
}

// policyOf reads the organization's unsandboxedPolicy, which the bridge delivers
// as an environment variable the package's setting names.
func policyOf(getenv func(string) string) string { return getenv(unsandboxedPolicyEnvName) }

// stateRoot is where connections live: BNBLOC_MYSQL_STATE_DIR, else PrivatePath
// under the user's config directory.
func stateRoot(getenv func(string) string) (string, error) {
	if d := strings.TrimSpace(getenv("BNBLOC_MYSQL_STATE_DIR")); d != "" {
		return d, nil
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", errors.New("there is no config directory to keep connections in: " + err.Error())
	}
	return filepath.Join(cfg, PrivatePath), nil
}

// openFile asks the operating system to show a file to the member.
func openFile(file string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", file)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", file)
	default:
		cmd = exec.Command("xdg-open", file)
	}
	return cmd.Start()
}

// Serve reads newline-delimited JSON-RPC from in and writes one response per
// request to out, until in closes. A notification gets no answer.
func Serve(ctx context.Context, s *Server, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			writeJSON(out, map[string]any{"jsonrpc": "2.0", "id": nil, "error": &rpcError{Code: -32700, Message: "parse error"}})
			continue
		}
		if len(req.ID) == 0 {
			continue
		}
		result, rerr := s.Dispatch(ctx, req.Method, req.Params)
		if rerr != nil {
			writeJSON(out, map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": rerr})
			continue
		}
		writeJSON(out, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}
	return sc.Err()
}

func writeJSON(w io.Writer, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	_, _ = w.Write(append(raw, '\n'))
}
