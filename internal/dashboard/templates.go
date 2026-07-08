package dashboard

import (
	"html/template"
	"io"
)

// Templates are declared inline (not embedded from disk) so operators reading
// the source can see the entire UI surface without a second file. The
// Phase 2 pages share a base layout defined once in dashPagesRoot.
//
// html/template (not text/template) auto-escapes every string reaching the
// output. Any operator-supplied string that eventually lands in HTML MUST
// travel via a template variable — never via fmt.Sprintf-into-HTML.

// pageStyles is the shared stylesheet. Kept as a template.HTML constant so
// html/template does not re-escape the CSS rules. It is not user-controlled.
const pageStyles = `<style>
  * { box-sizing: border-box; }
  body { font-family: system-ui, -apple-system, sans-serif; margin: 0;
         color: #222; background: #f8f8f8; }
  header { background: #24292f; color: #fff; padding: 0.9rem 1.4rem;
           display: flex; align-items: center; justify-content: space-between; }
  header h1 { margin: 0; font-size: 1.1rem; letter-spacing: .02em; }
  header form { margin: 0; }
  header nav a { color: #dfe4eb; text-decoration: none; margin-right: 1rem;
                 font-size: 0.95rem; }
  header nav a:hover { color: #fff; text-decoration: underline; }
  header nav a.active { color: #fff; font-weight: 600; }
  header button { background: transparent; color: #fff; border: 1px solid #4b5560;
                  padding: 0.35rem 0.7rem; border-radius: 4px; cursor: pointer; }
  main { max-width: 60rem; margin: 1.6rem auto; padding: 0 1.4rem; }
  h2 { margin-top: 0; font-size: 1.2rem; }
  .card { background: #fff; border: 1px solid #dcdcdc; border-radius: 6px;
          padding: 1rem 1.2rem; margin-bottom: 1.2rem; }
  .banner { padding: 0.7rem 1rem; border-radius: 4px; margin-bottom: 1rem;
            border: 1px solid transparent; font-size: 0.95rem; }
  .banner.err { background: #fdecea; border-color: #f5c6c1; color: #611a15; }
  .banner.ok  { background: #e6f4ea; border-color: #b7dfc1; color: #14532d; }
  .banner.warn{ background: #fff8e0; border-color: #eddfa1; color: #6b4c00; }
  dl.kv { display: grid; grid-template-columns: 8rem 1fr; gap: 0.3rem 1rem; margin: 0; }
  dl.kv dt { font-weight: 600; color: #444; }
  dl.kv dd { margin: 0; }
  table { border-collapse: collapse; width: 100%; margin-top: 0.4rem; }
  th, td { text-align: left; padding: 0.45rem 0.6rem;
           border-bottom: 1px solid #eee; font-size: 0.95rem; }
  th { background: #f2f4f6; }
  form.inline { display: inline; margin: 0; }
  form.inline button { padding: 0.25rem 0.55rem; font-size: 0.85rem;
                       border: 1px solid #cfcfcf; background: #fff;
                       border-radius: 3px; cursor: pointer; }
  form.stacked label { display: block; margin: 0.4rem 0 0.15rem; font-size: 0.9rem; }
  form.stacked input[type="text"] { width: 100%; padding: 0.4rem; border: 1px solid #ccc;
                                    border-radius: 4px; }
  form.stacked button { margin-top: 0.6rem; padding: 0.4rem 0.9rem;
                        background: #1f6feb; color: #fff; border: 0;
                        border-radius: 4px; cursor: pointer; }
  .muted { color: #666; }
  .pill { display: inline-block; padding: 0.05rem 0.5rem; border-radius: 10px;
          font-size: 0.85rem; }
  .pill.enforce { background: #e6f4ea; color: #14532d; }
  .pill.dryrun  { background: #fff8e0; color: #6b4c00; }
  .pill.up      { background: #e6f4ea; color: #14532d; }
  .pill.down    { background: #fdecea; color: #611a15; }
</style>`

// dashPagesRoot defines every named template shared by Phase 2 dashboard
// pages. Each concrete page (status, bans, allowlist) is cloned from this
// root and overrides the `content` block.
var dashPagesRoot = template.Must(template.New("root").Parse(`
{{define "layout"}}<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{{.Title}} — EzyShield</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  ` + pageStyles + `
</head>
<body>
  <header>
    <div>
      <h1>EzyShield</h1>
      <nav>
        <a href="/dashboard" class="{{if eq .Active "status"}}active{{end}}">Status</a>
        <a href="/dashboard/bans" class="{{if eq .Active "bans"}}active{{end}}">Bans</a>
        <a href="/dashboard/allowlist" class="{{if eq .Active "allowlist"}}active{{end}}">Allowlist</a>
      </nav>
    </div>
    <form method="post" action="/logout">
      <button type="submit">Sign out</button>
    </form>
  </header>
  <main>
    {{if .Error}}<div class="banner err">{{.Error}}</div>{{end}}
    {{if .Info}}<div class="banner ok">{{.Info}}</div>{{end}}
    {{if .Offline}}<div class="banner warn">Daemon is offline. Live data is not available until <code>ezyshield watch</code> is running.</div>{{end}}
    {{block "content" .}}{{end}}
  </main>
</body>
</html>{{end}}
`))

// pageEnvelope is the layout-level data passed to every rendered page.
// Concrete page data structs embed it so nav highlighting, error and info
// banners and the offline flag come from one place.
type pageEnvelope struct {
	Title   string
	Active  string
	Error   string
	Info    string
	Offline bool
}

// Compile each page once, at init, so template parse errors surface at
// startup rather than the first request.
var (
	statusPage = mustCompilePage(`
<div class="card">
  <h2>Daemon</h2>
  {{if .Data.Offline}}
    <p class="muted">The daemon socket did not answer. Start it with <code>ezyshield watch</code>.</p>
  {{else}}
    <dl class="kv">
      <dt>State</dt><dd><span class="pill {{if eq .Data.Daemon "running"}}up{{else}}down{{end}}">{{.Data.Daemon}}</span></dd>
      <dt>Mode</dt><dd><span class="pill {{if eq .Data.Mode "enforce"}}enforce{{else}}dryrun{{end}}">{{.Data.Mode}}</span></dd>
      <dt>Uptime</dt><dd>{{if .Data.Uptime}}{{.Data.Uptime}}{{else}}<span class="muted">—</span>{{end}}</dd>
      <dt>Version</dt><dd>{{if .Data.Version}}{{.Data.Version}}{{else}}<span class="muted">—</span>{{end}}</dd>
      <dt>Active bans</dt><dd>{{.Data.ActiveBans}}</dd>
    </dl>
  {{end}}
</div>

{{if .Data.BansByStrike}}
<div class="card">
  <h2>Bans by strike</h2>
  <table>
    <thead><tr><th>Bucket</th><th>Count</th></tr></thead>
    <tbody>
      {{range .Data.BansByStrike}}<tr><td>{{.Bucket}}</td><td>{{.Count}}</td></tr>{{end}}
    </tbody>
  </table>
</div>
{{end}}
`)

	bansPage = mustCompilePage(`
<div class="card">
  <h2>Manual ban</h2>
  <form class="stacked" method="post" action="/dashboard/ban">
    <label for="ban-ip">IP or CIDR</label>
    <input id="ban-ip" name="ip" type="text" required placeholder="203.0.113.7">
    <label for="ban-reason">Reason (optional)</label>
    <input id="ban-reason" name="reason" type="text" placeholder="brute force ssh">
    <button type="submit">Ban</button>
  </form>
</div>

<div class="card">
  <h2>Active bans</h2>
  {{if .Data.Offline}}
    <p class="muted">Live data unavailable while the daemon is offline.</p>
  {{else if .Data.Entries}}
    <table>
      <thead><tr>
        <th>IP</th><th>Strike</th><th>TTL</th><th>Country</th><th>ASN</th><th>Reason</th><th></th>
      </tr></thead>
      <tbody>
      {{range .Data.Entries}}
        <tr>
          <td>{{.IP}}</td>
          <td>{{.Strike}}</td>
          <td>{{.TTL}}</td>
          <td>{{if .Country}}{{.Country}}{{else}}<span class="muted">—</span>{{end}}</td>
          <td>{{if .ASN}}{{.ASN}}{{else}}<span class="muted">—</span>{{end}}</td>
          <td>{{if .Reason}}{{.Reason}}{{else}}<span class="muted">—</span>{{end}}</td>
          <td>
            <form class="inline" method="post" action="/dashboard/unban">
              <input type="hidden" name="ip" value="{{.IP}}">
              <button type="submit">Unban</button>
            </form>
          </td>
        </tr>
      {{end}}
      </tbody>
    </table>
  {{else}}
    <p class="muted">No active bans.</p>
  {{end}}
</div>
`)

	allowlistPage = mustCompilePage(`
<div class="card">
  <h2>Add to allowlist</h2>
  <form class="stacked" method="post" action="/dashboard/allow">
    <label for="allow-ip">IP or CIDR</label>
    <input id="allow-ip" name="ip" type="text" required placeholder="192.0.2.0/24">
    <label for="allow-reason">Reason (optional)</label>
    <input id="allow-reason" name="reason" type="text" placeholder="office egress">
    <button type="submit">Add</button>
  </form>
</div>

<div class="card">
  <h2>Allowlist entries</h2>
  {{if .Data.Offline}}
    <p class="muted">Live data unavailable while the daemon is offline.</p>
  {{else if .Data.Entries}}
    <table>
      <thead><tr>
        <th>Prefix</th><th>Expires</th><th>Reason</th>
      </tr></thead>
      <tbody>
      {{range .Data.Entries}}
        <tr>
          <td>{{.Prefix}}</td>
          <td>{{.Expires}}</td>
          <td>{{if .Reason}}{{.Reason}}{{else}}<span class="muted">—</span>{{end}}</td>
        </tr>
      {{end}}
      </tbody>
    </table>
  {{else}}
    <p class="muted">No allowlist entries.</p>
  {{end}}
</div>
`)
)

// mustCompilePage returns a template ready to Execute against a
// pageRenderData value with Data set to the concrete page payload.
func mustCompilePage(contentSrc string) *template.Template {
	t := template.Must(dashPagesRoot.Clone())
	template.Must(t.New("content").Parse(contentSrc))
	return t.Lookup("layout")
}

// pageRenderData is the top-level struct passed to Execute. It carries the
// envelope (Title, Active, Error, Info, Offline) and the page-specific
// payload under Data. Nesting keeps the layout template free of type
// assumptions about which concrete page it is rendering.
type pageRenderData struct {
	pageEnvelope
	Data any
}

func renderStatusPage(w io.Writer, data statusPageData) error {
	env := pageEnvelope{
		Title:   "Status",
		Active:  "status",
		Error:   data.Error,
		Info:    data.Info,
		Offline: data.Offline,
	}
	return statusPage.Execute(w, pageRenderData{pageEnvelope: env, Data: data})
}

func renderBansPage(w io.Writer, data bansPageData) error {
	env := pageEnvelope{
		Title:   "Bans",
		Active:  "bans",
		Error:   data.Error,
		Info:    data.Info,
		Offline: data.Offline,
	}
	return bansPage.Execute(w, pageRenderData{pageEnvelope: env, Data: data})
}

func renderAllowlistPage(w io.Writer, data allowlistPageData) error {
	env := pageEnvelope{
		Title:   "Allowlist",
		Active:  "allowlist",
		Error:   data.Error,
		Info:    data.Info,
		Offline: data.Offline,
	}
	return allowlistPage.Execute(w, pageRenderData{pageEnvelope: env, Data: data})
}

func renderLogin(w io.Writer, msg string) error {
	return loginTpl.Execute(w, struct{ Error string }{Error: msg})
}

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
