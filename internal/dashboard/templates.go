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

// pageStyles is the shared stylesheet. It is inline (kept as a Go const)
// so operators can audit the entire UI surface without hunting embedded
// assets, and so ezyshield dashboard stays a single self-contained
// binary. It is not user-controlled and never re-escaped.
//
// The rule set uses CSS custom properties so prefers-color-scheme: dark
// swaps palette without duplicating every selector. All layout numbers
// are in rem so the mobile break-point works cleanly for operators
// tunneling from a phone.
const pageStyles = `<style>
  :root {
    --bg: #f4f6f8; --panel: #ffffff; --panel-b: #dfe3e8;
    --text: #1c1f24; --muted: #5b6470;
    --accent: #1f6feb; --accent-f: #ffffff;
    --nav-bg: #24292f; --nav-fg: #dfe4eb; --nav-hi: #ffffff;
    --row-alt: #f7f9fb;
    --ok-bg: #e6f4ea; --ok-b: #b7dfc1; --ok-fg: #14532d;
    --err-bg: #fdecea; --err-b: #f5c6c1; --err-fg: #611a15;
    --warn-bg: #fff8e0; --warn-b: #eddfa1; --warn-fg: #6b4c00;
    --pill-en-bg: #e6f4ea; --pill-en-fg: #14532d;
    --pill-dr-bg: #ffedd5; --pill-dr-fg: #7c3400;
    --pill-up-bg: #e6f4ea; --pill-up-fg: #14532d;
    --pill-dn-bg: #fdecea; --pill-dn-fg: #611a15;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #12161c; --panel: #1c222b; --panel-b: #2a323d;
      --text: #e4e7eb; --muted: #8b95a2;
      --accent: #4a8afe; --accent-f: #0a0d12;
      --nav-bg: #0d1117; --nav-fg: #b3bcc8; --nav-hi: #ffffff;
      --row-alt: #232a34;
      --ok-bg: #163a24; --ok-b: #234f31; --ok-fg: #b8dcc4;
      --err-bg: #3f1717; --err-b: #6a2523; --err-fg: #f4c3bf;
      --warn-bg: #3a2c07; --warn-b: #5a4712; --warn-fg: #f0dea2;
      --pill-en-bg: #163a24; --pill-en-fg: #b8dcc4;
      --pill-dr-bg: #402c11; --pill-dr-fg: #f0c58e;
      --pill-up-bg: #163a24; --pill-up-fg: #b8dcc4;
      --pill-dn-bg: #3f1717; --pill-dn-fg: #f4c3bf;
    }
  }
  * { box-sizing: border-box; }
  html { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
         margin: 0; color: var(--text); background: var(--bg);
         font-size: 15px; line-height: 1.4; }
  header { background: var(--nav-bg); color: var(--nav-hi);
           padding: 0.75rem 1.2rem;
           display: flex; align-items: center; justify-content: space-between;
           position: sticky; top: 0; z-index: 20;
           box-shadow: 0 1px 0 rgba(0,0,0,.1); flex-wrap: wrap; gap: 0.6rem; }
  header .brand { display: flex; align-items: center; gap: 0.9rem; flex-wrap: wrap; }
  header h1 { margin: 0; font-size: 1.05rem; letter-spacing: .02em; color: var(--nav-hi); }
  header form { margin: 0; }
  header nav { display: flex; flex-wrap: wrap; gap: 1rem; }
  header nav a { color: var(--nav-fg); text-decoration: none; font-size: 0.95rem;
                 padding: 0.15rem 0.15rem; border-bottom: 2px solid transparent; }
  header nav a:hover { color: var(--nav-hi); }
  header nav a.active { color: var(--nav-hi); font-weight: 600;
                        border-bottom-color: var(--accent); }
  header .actions { display: flex; align-items: center; gap: 1rem; }
  header button { background: transparent; color: var(--nav-hi);
                  border: 1px solid #4b5560; padding: 0.35rem 0.7rem;
                  border-radius: 4px; cursor: pointer; font-size: 0.85rem; }
  main { max-width: 60rem; margin: 1.3rem auto; padding: 0 1.2rem; }
  h2 { margin-top: 0; font-size: 1.15rem; }
  .card { background: var(--panel); border: 1px solid var(--panel-b);
          border-radius: 6px; padding: 1rem 1.2rem; margin-bottom: 1.1rem; }
  .banner { padding: 0.65rem 0.95rem; border-radius: 4px; margin-bottom: 0.9rem;
            border: 1px solid transparent; font-size: 0.94rem;
            transition: opacity 0.4s ease; }
  .banner.hide { opacity: 0; pointer-events: none; }
  .banner.err { background: var(--err-bg); border-color: var(--err-b); color: var(--err-fg); }
  .banner.ok  { background: var(--ok-bg);  border-color: var(--ok-b);  color: var(--ok-fg); }
  .banner.warn{ background: var(--warn-bg);border-color: var(--warn-b);color: var(--warn-fg); }
  dl.kv { display: grid; grid-template-columns: 8rem 1fr; gap: 0.3rem 1rem; margin: 0; }
  dl.kv dt { font-weight: 600; color: var(--muted); }
  dl.kv dd { margin: 0; color: var(--text); }
  table { border-collapse: collapse; width: 100%; margin-top: 0.4rem; font-size: 0.93rem; }
  th, td { text-align: left; padding: 0.5rem 0.6rem;
           border-bottom: 1px solid var(--panel-b); }
  th { background: var(--row-alt); font-weight: 600; }
  tbody tr:nth-child(even) { background: var(--row-alt); }
  .scroll { overflow-x: auto; }
  form.inline { display: inline; margin: 0; }
  form.inline button { padding: 0.25rem 0.6rem; font-size: 0.85rem;
                       border: 1px solid var(--panel-b); background: var(--panel);
                       color: var(--text); border-radius: 4px; cursor: pointer; }
  form.stacked label { display: block; margin: 0.5rem 0 0.2rem; font-size: 0.9rem; }
  form.stacked input[type="text"] { width: 100%; padding: 0.5rem;
                                    border: 1px solid var(--panel-b);
                                    background: var(--panel); color: var(--text);
                                    border-radius: 4px; }
  form.stacked button { margin-top: 0.7rem; padding: 0.5rem 1rem;
                        background: var(--accent); color: var(--accent-f);
                        border: 0; border-radius: 4px; cursor: pointer;
                        font-weight: 500; }
  .muted { color: var(--muted); }
  .pill { display: inline-block; padding: 0.05rem 0.55rem; border-radius: 10px;
          font-size: 0.82rem; font-weight: 500; }
  .pill.enforce { background: var(--pill-en-bg); color: var(--pill-en-fg); }
  .pill.dryrun  { background: var(--pill-dr-bg); color: var(--pill-dr-fg); }
  .pill.up      { background: var(--pill-up-bg); color: var(--pill-up-fg); }
  .pill.down    { background: var(--pill-dn-bg); color: var(--pill-dn-fg); }
  #live-dot { display: inline-flex; align-items: center; gap: 0.3rem;
              color: #8b95a2; font-size: 0.8rem; }
  #live-dot .dot { width: 0.55rem; height: 0.55rem; border-radius: 50%;
                   background: #6b7580; transition: background 0.2s ease; }
  #live-dot.on .dot { background: #40c463;
                      animation: livepulse 2s ease-out infinite; }
  #live-dot.on { color: var(--nav-hi); }
  @keyframes livepulse {
    0%   { box-shadow: 0 0 0 0 rgba(64,196,99,.55); }
    70%  { box-shadow: 0 0 0 6px rgba(64,196,99,0); }
    100% { box-shadow: 0 0 0 0 rgba(64,196,99,0); }
  }
  .ladder { display: flex; align-items: center; gap: 0.35rem;
            flex-wrap: wrap; margin-top: 0.55rem; }
  .ladder .step { display: flex; align-items: center; gap: 0.3rem;
                  padding: 0.15rem 0.55rem; border-radius: 14px;
                  border: 1px solid var(--panel-b); background: var(--panel);
                  font-size: 0.82rem; color: var(--muted); }
  .ladder .step.reached { border-color: transparent;
                          background: var(--pill-en-bg); color: var(--pill-en-fg); }
  .ladder .step.current { border-color: var(--accent); }
  .ladder .step time { color: var(--muted); font-size: 0.75rem; }
  .ladder .arrow { color: var(--muted); }
  .timeline-row h3 { margin: 0 0 0.15rem; font-size: 1rem;
                     font-family: ui-monospace, "SFMono-Regular", Menlo, monospace; }
  .timeline-row .meta { color: var(--muted); font-size: 0.85rem; }
  @media (max-width: 40rem) {
    header { padding: 0.6rem 0.8rem; }
    header .brand { gap: 0.6rem; }
    main { padding: 0 0.8rem; margin-top: 0.9rem; }
    .card { padding: 0.85rem 0.9rem; }
    dl.kv { grid-template-columns: 1fr; }
    dl.kv dt { margin-top: 0.4rem; }
    th, td { padding: 0.35rem 0.4rem; font-size: 0.85rem; }
  }
</style>`

// flashScript auto-dismisses success/error banners marked
// .auto-dismiss after 5 s. The persistent "warn" banner (daemon offline)
// is not marked so it stays visible until the daemon comes back.
const flashScript = `
(function () {
  var banners = document.querySelectorAll('.banner.auto-dismiss');
  if (!banners.length) return;
  setTimeout(function () {
    banners.forEach(function (b) {
      b.classList.add('hide');
      setTimeout(function () { b.remove(); }, 500);
    });
  }, 5000);
})();
`

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
    <div class="brand">
      <h1>EzyShield</h1>
      <nav>
        <a href="/dashboard" class="{{if eq .Active "status"}}active{{end}}">Status</a>
        <a href="/dashboard/bans" class="{{if eq .Active "bans"}}active{{end}}">Bans</a>
        <a href="/dashboard/allowlist" class="{{if eq .Active "allowlist"}}active{{end}}">Allowlist</a>
        <a href="/dashboard/events" class="{{if eq .Active "events"}}active{{end}}">Events</a>
        <a href="/dashboard/timeline" class="{{if eq .Active "timeline"}}active{{end}}">Timeline</a>
      </nav>
    </div>
    <div class="actions">
      <span id="live-dot" title="Live updates" aria-label="Live updates">
        <span class="dot"></span><span class="live-label">live</span>
      </span>
      <form method="post" action="/logout">
        <input type="hidden" name="csrf_token" value="{{.CSRF}}">
        <button type="submit">Sign out</button>
      </form>
    </div>
  </header>
  <main>
    {{if .Error}}<div class="banner err auto-dismiss">{{.Error}}</div>{{end}}
    {{if .Info}}<div class="banner ok auto-dismiss">{{.Info}}</div>{{end}}
    {{if .Offline}}<div class="banner warn">Daemon is offline. Live data is not available until <code>ezyshield run</code> is running.</div>{{end}}
    {{block "content" .}}{{end}}
  </main>
  <script>` + liveScript + flashScript + `</script>
  {{block "extraScript" .}}{{end}}
</body>
</html>{{end}}
`))

// pageEnvelope is the layout-level data passed to every rendered page.
// Concrete page data structs embed it so nav highlighting, error and info
// banners, the offline flag and the CSRF token all come from one place.
type pageEnvelope struct {
	Title   string
	Active  string
	Error   string
	Info    string
	Offline bool
	CSRF    string
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
    <input type="hidden" name="csrf_token" value="{{.CSRF}}">
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
    <div class="scroll"><table>
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
              <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
              <input type="hidden" name="ip" value="{{.IP}}">
              <button type="submit">Unban</button>
            </form>
          </td>
        </tr>
      {{end}}
      </tbody>
    </table></div>
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
    <input type="hidden" name="csrf_token" value="{{.CSRF}}">
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
    <div class="scroll"><table>
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
    </table></div>
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
    <div class="scroll"><table id="events-table">
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
    </table></div>
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

	timelinePage = mustCompilePage(`
{{define "content"}}
<div class="card">
  <h2>Strike timeline</h2>
  <p class="muted">One card per currently-banned IP with the 5-strike ladder
  reconstructed from the recent audit trail. Read-only.</p>
</div>
{{if .Data.Entries}}
  {{range .Data.Entries}}
    <div class="card timeline-row">
      <h3>{{.IP}}</h3>
      <p class="meta">
        Current strike {{.CurrentTier}}
        <span class="muted">·</span>
        TTL {{.CurrentTTL}}
        {{if .Country}}<span class="muted">·</span> {{.Country}}{{end}}
        {{if .ASN}}<span class="muted">·</span> {{.ASN}}{{end}}
      </p>
      <div class="ladder">
        {{range $i, $step := .Steps}}
          {{if $i}}<span class="arrow">→</span>{{end}}
          <span class="step {{if $step.Reached}}reached{{end}}{{if eq $step.Strike $.CurrentTier}} current{{end}}"
                title="{{if $step.Reached}}Reached{{if $step.RecordedAt}} at {{$step.RecordedAt}}{{end}}{{if $step.Reason}} — {{$step.Reason}}{{end}}{{else}}Not reached yet{{end}}">
            <strong>#{{$step.Strike}}</strong>
            {{if $step.RecordedAt}}<time>{{$step.RecordedAt}}</time>{{end}}
          </span>
        {{end}}
      </div>
    </div>
  {{end}}
{{else if not .Data.Offline}}
  <div class="card"><p class="muted">No active bans to plot.</p></div>
{{end}}
{{end}}
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

func renderStatusPage(w io.Writer, csrf string, data statusPageData) error {
	return statusPage.Execute(w, pageRenderData{
		pageEnvelope: pageEnvelope{
			Title: "Status", Active: "status",
			Error: data.Error, Info: data.Info, Offline: data.Offline, CSRF: csrf,
		},
		Data: data,
	})
}

func renderBansPage(w io.Writer, csrf string, data bansPageData) error {
	return bansPage.Execute(w, pageRenderData{
		pageEnvelope: pageEnvelope{
			Title: "Bans", Active: "bans",
			Error: data.Error, Info: data.Info, Offline: data.Offline, CSRF: csrf,
		},
		Data: data,
	})
}

func renderEventsPage(w io.Writer, csrf string, data eventsPageData) error {
	return eventsPage.Execute(w, pageRenderData{
		pageEnvelope: pageEnvelope{
			Title: "Events", Active: "events",
			Error: data.Error, Info: data.Info, Offline: data.Offline, CSRF: csrf,
		},
		Data: data,
	})
}

func renderAllowlistPage(w io.Writer, csrf string, data allowlistPageData) error {
	return allowlistPage.Execute(w, pageRenderData{
		pageEnvelope: pageEnvelope{
			Title: "Allowlist", Active: "allowlist",
			Error: data.Error, Info: data.Info, Offline: data.Offline, CSRF: csrf,
		},
		Data: data,
	})
}

func renderTimelinePage(w io.Writer, csrf string, data timelinePageData) error {
	return timelinePage.Execute(w, pageRenderData{
		pageEnvelope: pageEnvelope{
			Title: "Timeline", Active: "timeline",
			Error: data.Error, Info: data.Info, Offline: data.Offline, CSRF: csrf,
		},
		Data: data,
	})
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
