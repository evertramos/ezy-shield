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
  #live-dot { display: inline-flex; align-items: center; gap: 0.3rem;
              color: #b7bec8; font-size: 0.8rem; }
  #live-dot .dot { width: 0.5rem; height: 0.5rem; border-radius: 50%;
                   background: #6b7580; transition: background 0.2s ease; }
  #live-dot.on .dot { background: #40c463; box-shadow: 0 0 0 0 rgba(64,196,99,.5);
                      animation: livepulse 2s ease-out infinite; }
  #live-dot.on { color: #dfe4eb; }
  @keyframes livepulse {
    0%   { box-shadow: 0 0 0 0 rgba(64,196,99,.55); }
    70%  { box-shadow: 0 0 0 6px rgba(64,196,99,0); }
    100% { box-shadow: 0 0 0 0 rgba(64,196,99,0); }
  }
</style>`

// liveScript wires the shared /dashboard/ws socket. It exposes a small
// window.EzyLive API that per-page scripts hook into to react to events
// (e.g. prepend a row to the events table, reload the bans page).
// Kept intentionally small: no external JS libraries; ~1 KB minified.
const liveScript = `
(function () {
  var dot = document.getElementById('live-dot');
  function setLive(on) { if (dot) dot.classList.toggle('on', !!on); }
  setLive(false);
  var scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  var url = scheme + '//' + window.location.host + '/dashboard/ws';
  var handlers = { audit: [], refresh: [] };
  window.EzyLive = {
    on: function (kind, fn) { (handlers[kind] || (handlers[kind] = [])).push(fn); }
  };
  var backoff = 1000;
  function connect() {
    var ws;
    try { ws = new WebSocket(url); } catch (e) { return schedule(); }
    ws.onopen = function () { setLive(true); backoff = 1000; };
    ws.onclose = function () { setLive(false); schedule(); };
    ws.onerror = function () { setLive(false); };
    ws.onmessage = function (ev) {
      var msg;
      try { msg = JSON.parse(ev.data); } catch (e) { return; }
      if (msg.type === 'refresh') { window.location.reload(); return; }
      var list = handlers[msg.type] || [];
      for (var i = 0; i < list.length; i++) {
        try { list[i](msg); } catch (e) { /* ignore per-handler errors */ }
      }
    };
  }
  function schedule() {
    setTimeout(connect, backoff);
    backoff = Math.min(backoff * 2, 30000);
  }
  connect();
})();
`

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
        <a href="/dashboard/events" class="{{if eq .Active "events"}}active{{end}}">Events</a>
      </nav>
    </div>
    <div style="display:flex;align-items:center;gap:1rem;">
      <span id="live-dot" title="Live updates" aria-label="Live updates">
        <span class="dot"></span><span class="live-label">live</span>
      </span>
      <form method="post" action="/logout">
        <button type="submit">Sign out</button>
      </form>
    </div>
  </header>
  <main>
    {{if .Error}}<div class="banner err">{{.Error}}</div>{{end}}
    {{if .Info}}<div class="banner ok">{{.Info}}</div>{{end}}
    {{if .Offline}}<div class="banner warn">Daemon is offline. Live data is not available until <code>ezyshield watch</code> is running.</div>{{end}}
    {{block "content" .}}{{end}}
  </main>
  <script>` + liveScript + `</script>
  {{block "extraScript" .}}{{end}}
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
{{define "content"}}
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
{{end}}
`)

	bansPage = mustCompilePage(`
{{define "content"}}
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
{{end}}
{{define "extraScript"}}<script>
  // Any new audit event that touches the ban surface triggers a full
  // reload — cheap in Phase 3 and keeps the row shape identical to the
  // server-rendered page. A burst larger than the bus coalesces already
  // arrives as a "refresh" and is handled globally by liveScript.
  window.EzyLive && window.EzyLive.on('audit', function (msg) {
    var op = msg.entry && msg.entry.op;
    if (op && (op.indexOf('ban') === 0 || op === 'unban' || op === 'dry_ban')) {
      window.location.reload();
    }
  });
</script>{{end}}
`)

	allowlistPage = mustCompilePage(`
{{define "content"}}
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
{{end}}
{{define "extraScript"}}<script>
  window.EzyLive && window.EzyLive.on('audit', function (msg) {
    var op = msg.entry && msg.entry.op;
    if (op && op.indexOf('allow') === 0) {
      window.location.reload();
    }
  });
</script>{{end}}
`)

	eventsPage = mustCompilePage(`
{{define "content"}}
<div class="card">
  <h2>Recent events (last 100)</h2>
  {{if .Data.Offline}}
    <p class="muted">Live data unavailable while the daemon is offline.</p>
  {{else}}
    <table id="events-table">
      <thead><tr>
        <th>Time (UTC)</th><th>Operation</th><th>IP</th><th>Strike</th><th>TTL</th><th>Reason</th>
      </tr></thead>
      <tbody id="events-tbody">
      {{if .Data.Entries}}
        {{range .Data.Entries}}
        <tr data-audit-id="{{.ID}}">
          <td>{{.RecordedAt}}</td>
          <td>{{.Op}}</td>
          <td>{{.IP}}</td>
          <td>{{.Strike}}</td>
          <td>{{if gt .TTLSeconds 0}}{{.TTLSeconds}}s{{else}}<span class="muted">—</span>{{end}}</td>
          <td>{{if .Reason}}{{.Reason}}{{else}}<span class="muted">—</span>{{end}}</td>
        </tr>
        {{end}}
      {{else}}
        <tr id="events-empty"><td colspan="6" class="muted">No events recorded yet.</td></tr>
      {{end}}
      </tbody>
    </table>
  {{end}}
</div>
{{end}}
{{define "extraScript"}}<script>
  (function () {
    var tbody = document.getElementById('events-tbody');
    if (!tbody) return;
    function esc(s) {
      var d = document.createElement('div');
      d.textContent = s == null ? '' : String(s);
      return d.innerHTML;
    }
    window.EzyLive && window.EzyLive.on('audit', function (msg) {
      var e = msg.entry;
      if (!e || tbody.querySelector('tr[data-audit-id="' + esc(e.id) + '"]')) return;
      var empty = document.getElementById('events-empty');
      if (empty) empty.remove();
      var tr = document.createElement('tr');
      tr.setAttribute('data-audit-id', String(e.id));
      var reason = e.reason ? esc(e.reason) : '<span class="muted">—</span>';
      var ttl = e.ttl_seconds > 0 ? esc(e.ttl_seconds) + 's' : '<span class="muted">—</span>';
      tr.innerHTML =
        '<td>' + esc(e.recorded_at) + '</td>' +
        '<td>' + esc(e.op) + '</td>' +
        '<td>' + esc(e.ip) + '</td>' +
        '<td>' + esc(e.strike) + '</td>' +
        '<td>' + ttl + '</td>' +
        '<td>' + reason + '</td>';
      tbody.insertBefore(tr, tbody.firstChild);
      // Cap at 100 rendered rows so the DOM doesn't grow unbounded.
      while (tbody.children.length > 100) {
        tbody.removeChild(tbody.lastElementChild);
      }
    });
  })();
</script>{{end}}
`)
)

// mustCompilePage returns a template ready to Execute against a
// pageRenderData value. bundle must contain a `{{define "content"}}…{{end}}`
// block and may optionally define `{{define "extraScript"}}…{{end}}` for
// per-page JavaScript that hooks into the shared window.EzyLive API.
func mustCompilePage(bundle string) *template.Template {
	t := template.Must(dashPagesRoot.Clone())
	template.Must(t.Parse(bundle))
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

func renderEventsPage(w io.Writer, data eventsPageData) error {
	env := pageEnvelope{
		Title:   "Events",
		Active:  "events",
		Error:   data.Error,
		Info:    data.Info,
		Offline: data.Offline,
	}
	return eventsPage.Execute(w, pageRenderData{pageEnvelope: env, Data: data})
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
