package main

import (
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Page is the loopback page on which the member, and only the member, types a
// password or clicks Allow. It is served by this tool and its address is never
// given to the agent: the member reaches it through a one-time file the tool
// asks the operating system to open (pending.go).
type Page struct {
	p  *Pending
	st *Store
}

func NewPage(p *Pending, st *Store) *Page { return &Page{p: p, st: st} }

func (pg *Page) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	mux.HandleFunc("/a/", pg.action)
	mux.HandleFunc("/a.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		fmt.Fprint(w, pageJS)
	})
	return pg.guard(mux)
}

// guard refuses a request not meant for this page. The page listens on a
// loopback port a web page the member has open could try to reach: a Host that
// is not a loopback address is a DNS-rebinding attempt, and a request a browser
// marks as from another site or origin is a forged post.
func (pg *Page) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Host
		if host, _, err := net.SplitHostPort(h); err == nil {
			h = host
		}
		if ip := net.ParseIP(strings.Trim(h, "[]")); h != "localhost" && (ip == nil || !ip.IsLoopback()) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if s := r.Header.Get("Sec-Fetch-Site"); s != "" && s != "same-origin" && s != "none" {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" {
			u, err := url.Parse(o)
			if err != nil || u.Host != r.Host {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
		}
		hd := w.Header()
		hd.Set("Cache-Control", "no-store")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func (pg *Page) action(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/a/")
	switch r.Method {
	case http.MethodGet:
		// The token is in the address's fragment, which the browser never sends;
		// a GET gets the form without it, so reaching the port is not enough.
		pg.form(w, id)
	case http.MethodPost:
		pg.answer(w, r, id)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (pg *Page) form(w http.ResponseWriter, id string) {
	st, found := pg.p.Peek(id)
	if !found {
		state, known := pg.p.State(id)
		msg := "This request is not here (it may have expired)."
		if known {
			msg = "This request is " + state.String() + "."
		}
		w.WriteHeader(http.StatusGone)
		fmt.Fprintf(w, pageHead+"<p>%s</p>", html.EscapeString(msg))
		return
	}
	_ = st
	act, ok := pg.p.peekAction(id)
	if !ok {
		http.NotFound(w, nil)
		return
	}
	var b strings.Builder
	b.WriteString(pageHead)
	fmt.Fprintf(&b, `<form method="post" action="/a/%s"><input type="hidden" name="token" id="token">`, html.EscapeString(id))
	switch act.Kind {
	case ActPassword:
		c := act.Conn
		fmt.Fprintf(&b, `<h1>Connect %s</h1><p>%s@%s:%d / %s &middot; TLS: %s</p>`+
			`<p>Your agent asked to connect this database. Type its password here; it is saved on this computer only and is never sent to the agent or the room.</p>`+
			`<label>Password <input type="password" name="password" autocomplete="off" autofocus></label>`,
			html.EscapeString(act.Alias), html.EscapeString(c.User), html.EscapeString(c.Host), c.Port, html.EscapeString(c.Database), tlsLabel(c.TLS))
		b.WriteString(`<button name="decision" value="allow">Save connection</button> <button name="decision" value="deny">Cancel</button>`)
	case ActAllow:
		fmt.Fprintf(&b, `<h1>Allow this change on %s?</h1><pre>%s</pre>`+
			`<p>Your agent wants to run exactly this statement. It runs once, and only if you allow it.</p>`,
			html.EscapeString(act.Alias), html.EscapeString(act.SQL))
		b.WriteString(`<button name="decision" value="allow">Allow</button> <button name="decision" value="deny">Deny</button>`)
	}
	b.WriteString(`</form><script src="/a.js"></script>`)
	fmt.Fprint(w, b.String())
}

func tlsLabel(m string) string {
	if m == TLSSkip {
		return `<b style="color:#b00">certificate NOT verified</b>`
	}
	return "certificate verified"
}

func (pg *Page) answer(w http.ResponseWriter, r *http.Request, id string) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token := r.PostForm.Get("token")
	act, err := pg.p.Verify(id, token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	allow := r.PostForm.Get("decision") == "allow"
	if allow && act.Kind == ActPassword {
		password := r.PostForm.Get("password")
		if password == "" {
			http.Error(w, "type the password, or Cancel", http.StatusBadRequest)
			return
		}
		if err := pg.st.Put(act.Conn, password); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}
	if err := pg.p.Resolve(id, token, allow); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	msg := "Done. You can close this tab and go back to your agent."
	if !allow {
		msg = "Cancelled. Nothing was changed."
	}
	fmt.Fprintf(w, pageHead+"<p>%s</p>", html.EscapeString(msg))
}

const pageHead = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>bnbloc MySQL</title>` +
	`<style>body{font:16px system-ui;max-width:42rem;margin:3rem auto;padding:0 1rem}pre{background:#f4f4f4;padding:1rem;overflow:auto;white-space:pre-wrap}button{font:inherit;padding:.5rem 1rem}input{font:inherit}</style>`

// pageJS moves the token from the address's fragment into the form and removes
// it from the address bar.
const pageJS = `(function(){var t=location.hash.slice(1);var f=document.getElementById("token");if(f)f.value=t;history.replaceState(null,"",location.pathname)})();`
