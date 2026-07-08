package dashboard

import (
	"html/template"
	"io"
)

// The templates are declared inline (not embedded from disk) because Phase 1
// carries only a login page and a placeholder index; both are ~1 KB of HTML.
// When Phase 2 adds live views the assets move to //go:embed static/*.
//
// html/template is used (not text/template) so operator-supplied strings —
// error messages, usernames rendered back on error, etc. — are escaped by
// default. Any string that reaches these templates from user input MUST come
// via a template variable, never via fmt.Sprintf-into-HTML.

var loginTpl = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>EzyShield — Sign in</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 22rem;
           margin: 5rem auto; padding: 1rem; color: #222; }
    h1 { margin: 0 0 1rem; font-size: 1.4rem; }
    label { display: block; margin: .5rem 0 .25rem; font-size: .9rem; }
    input { width: 100%; padding: .5rem; box-sizing: border-box;
            border: 1px solid #bbb; border-radius: 4px; }
    button { margin-top: 1rem; padding: .5rem 1rem;
             background: #1f6feb; color: #fff; border: 0; border-radius: 4px;
             cursor: pointer; }
    .err { color: #c00; margin: .5rem 0; }
    .hint { color: #666; font-size: .8rem; margin-top: 1.5rem; }
  </style>
</head>
<body>
  <h1>EzyShield</h1>
  {{if .Error}}<p class="err">{{.Error}}</p>{{end}}
  <form method="post" action="/login">
    <label for="u">User</label>
    <input id="u" name="username" autocomplete="username" required autofocus>
    <label for="p">Password</label>
    <input id="p" name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Sign in</button>
  </form>
  <p class="hint">Dashboard is bound to loopback only. See docs/dashboard.md for remote access via SSH port-forward or Cloudflare Tunnel.</p>
</body>
</html>`))

var indexTpl = template.Must(template.New("index").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>EzyShield Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; max-width: 42rem;
           margin: 3rem auto; padding: 1rem; color: #222; }
    header { display: flex; justify-content: space-between; align-items: center; }
    h1 { margin: 0; font-size: 1.4rem; }
    button { padding: .4rem .8rem; border: 1px solid #bbb;
             background: #fff; border-radius: 4px; cursor: pointer; }
    .card { margin-top: 2rem; padding: 1rem; border: 1px solid #ddd;
            border-radius: 6px; background: #fafafa; }
  </style>
</head>
<body>
  <header>
    <h1>EzyShield</h1>
    <form method="post" action="/logout" style="margin:0">
      <button type="submit">Sign out</button>
    </form>
  </header>
  <div class="card">
    <p>Dashboard scaffold — Phase 1.</p>
    <p>Live status, active bans, strike history, allowlist and log tail land in Phase 2 once the daemon RPC surface is wired.</p>
  </div>
</body>
</html>`))

func renderLogin(w io.Writer, msg string) error {
	return loginTpl.Execute(w, struct{ Error string }{Error: msg})
}

func renderIndex(w io.Writer) error {
	return indexTpl.Execute(w, nil)
}
