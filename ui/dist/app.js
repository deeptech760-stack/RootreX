/* RootreX UI — talks to the loopback API, renders the Tactical HUD.
 * Motion is functional: new hosts flash in, state changes pulse, the STOP
 * control breathes while armed, the rate spark tracks observed volume.
 */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const api = (path, opts) =>
    fetch("/api" + path, { headers: { "Content-Type": "application/json" }, ...opts })
      .then((r) => r.json())
      .catch((e) => ({ error: String(e) }));
  const post = (path, body) =>
    api(path, { method: "POST", body: body ? JSON.stringify(body) : undefined });
  const del = (path) => api(path, { method: "DELETE" });

  const G = window.gsap;
  const knownMacs = new Set();
  const prevStatus = new Map();
  let lastDevSig = "";
  let lastBytes = null;
  const rateHist = [];
  let stopPulse = null;
  const bwHist = [];
  let lastBw = { d: null, u: null, t: null };

  // ------------------------------------------------------------- formatting
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const clock = (iso) => { try { return new Date(iso).toLocaleTimeString("en-GB"); } catch { return "—"; } };
  const kb = (n) => n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB";
  const rate = (n) => (!n || n < 1) ? "—" : kb(n) + "/s";

  function toast(msg, bad) {
    const el = $("#st-log");
    el.textContent = (bad ? "⚠ " : "› ") + msg;
    el.style.color = bad ? "var(--red)" : "var(--fg-dim)";
  }

  // ------------------------------------------------------------- render: context
  function renderContext(s) {
    const c = s.context;
    $("#ctx-iface").textContent = c ? c.iface.slice(0, 22) : "—";
    $("#ctx-local").textContent = c ? `${c.local_ip}` : "—";
    $("#ctx-gw").textContent = c ? c.gateway_ip : "—";
    $("#ctx-cidr").textContent = c ? c.cidr : "—";
    $("#e-cidr").textContent = c ? c.cidr : "the subnet";
    $("#st-engine").textContent = s.ok ? "ready" : "offline";
    $("#st-engine").style.color = s.ok ? "var(--green)" : "var(--red)";

    const chip = $("#consent-chip");
    chip.classList.toggle("ok", !!s.consent);
    $("#consent-text").textContent = s.consent ? "Authorized" : "No consent";
    $("#stop-all").disabled = !s.consent;
  }

  function renderEngineError(s) {
    const box = $("#lan-error");
    if (s.ok || !s.error) { box.innerHTML = ""; return; }
    box.innerHTML = `<div class="banner-error">Engine offline — ${esc(s.error)}. Check that Npcap ≥1.3.0 is installed and RootreX is running as Administrator.</div>`;
  }

  // ---------------------------------------------------- render: prerequisites
  function renderPreflight(s) {
    const bar = $("#preflight-bar");
    const pf = s.preflight;
    if (!pf || !pf.items) { bar.innerHTML = ""; return; }
    const bad = pf.items.filter((i) => !i.ok);
    if (!bad.length) { bar.innerHTML = ""; return; }
    bar.innerHTML = bad.map((i) => {
      const install = i.installer ? `<button class="pf-btn" data-pf-install="${i.key}">Download &amp; install</button>` : "";
      const page = i.page ? `<button class="pf-btn ghost" data-pf-open="${i.key}">Download page</button>` : "";
      return `<div class="preflight-row ${i.required ? "req" : "opt"}">
        <span class="pf-tag">${i.required ? "MISSING" : "OPTIONAL"}</span>
        <span class="pf-name">${esc(i.name)}</span>
        <span class="pf-detail">${esc(i.detail)}</span>
        ${install}${page}
      </div>`;
    }).join("") + `<button class="pf-btn ghost" id="pf-recheck">Re-check</button>`;
  }

  // ------------------------------------------------------------- render: scanner
  function controlCell(d) {
    const mode = d.status;
    if (d.kind === "self") return '<span class="noctl">this device</span>';
    if (d.kind === "gateway") return '<span class="noctl">gateway</span>';
    if (mode === "cut")
      return `<button class="btn on-red" data-act="restore" data-mac="${d.mac}" data-ip="${d.ip}">◼ Cut · Unblock</button>`;
    if (mode === "routed")
      return `<button class="btn on-cyan" data-act="restore" data-mac="${d.mac}" data-ip="${d.ip}">◼ Routed · Restore</button>`;
    return `<button class="btn block" data-act="block" data-mac="${d.mac}" data-ip="${d.ip}">Block</button>
            <button class="btn route" data-act="route" data-mac="${d.mac}" data-ip="${d.ip}">Route</button>`;
  }

  const ipNum = (ip) => String(ip).split(".").reduce((a, o) => a * 256 + (+o || 0), 0);
  const KIND_RANK = { gateway: 0, self: 1, device: 2 };

  function deviceRow(d) {
    const st = d.status || "live";
    const nm = d.name || (d.kind === "gateway" ? "Router" : "");
    const chip = d.kind === "self" ? '<span class="chip you">YOU</span>'
               : d.kind === "gateway" ? '<span class="chip router">ROUTER</span>' : "";
    const nameCell = nm ? `<span class="dev-name">${esc(nm)}</span>` : '<span class="unk">unknown</span>';
    return `<tr data-mac="${d.mac}" class="${d.online ? "" : "offline"} ${d.kind}">
      <td><span class="state ${d.online ? st : "off"}"><span class="dot"></span></span></td>
      <td class="dev">${nameCell}${chip}</td>
      <td class="ip">${esc(d.ip)}</td>
      <td class="mac">${esc(d.mac)}</td>
      <td class="vendor">${esc(d.vendor)}</td>
      <td class="seen">${clock(d.last_seen)}</td>
      <td><div class="acts">${controlCell(d)}</div></td>
    </tr>`;
  }

  function renderDevices(s) {
    const devs = s.devices || [];
    const onlineN = devs.filter((d) => d.online).length;
    $("#dev-count").textContent = `${onlineN} online · ${devs.length} known`;
    $("#dev-empty").style.display = devs.length ? "none" : "flex";

    // online first (router → you → devices → by IP); offline remembered at the bottom
    const sorted = [...devs].sort((a, b) => {
      if (a.online !== b.online) return a.online ? -1 : 1;
      const ra = KIND_RANK[a.kind] ?? 3, rb = KIND_RANK[b.kind] ?? 3;
      if (ra !== rb) return ra - rb;
      return ipNum(a.ip) - ipNum(b.ip);
    });

    // Only rebuild the table when the device set/status actually changed —
    // otherwise a 0.8s refresh landing mid-click would swallow the Block/Route tap.
    const sig = sorted.map((d) => `${d.mac}|${d.ip}|${d.status}|${d.online}|${d.name}`).join(";");
    if (sig === lastDevSig) return;
    lastDevSig = sig;

    const tb = $("#dev-rows");
    let html = "", divider = false;
    for (const d of sorted) {
      if (!d.online && !divider) {
        divider = true;
        const off = sorted.filter((x) => !x.online).length;
        html += `<tr class="divider"><td colspan="7">Offline · remembered (${off})</td></tr>`;
      }
      html += deviceRow(d);
    }
    tb.innerHTML = html;

    // animate genuinely new rows + flash status changes
    devs.forEach((d) => {
      const row = tb.querySelector(`tr[data-mac="${CSS.escape(d.mac)}"]`);
      if (!row) return;
      if (!knownMacs.has(d.mac)) {
        knownMacs.add(d.mac);
        if (G) G.from(row, { opacity: 0, x: -14, duration: 0.4, ease: "power2.out" });
      }
      const was = prevStatus.get(d.mac);
      if (was && was !== d.status) {
        const cell = row.querySelector(".state");
        if (G) G.fromTo(cell, { filter: "brightness(2.6)" }, { filter: "brightness(1)", duration: 0.7 });
      }
      prevStatus.set(d.mac, d.status);
    });
  }

  // ------------------------------------------------------------- render: activity / board
  const PROTO_COLORS = { "HTTP/3": "var(--amber)", "HTTP/2": "var(--violet)",
    "HTTP/1.1": "#ff8a3d", "TLS": "var(--violet)", "DNS": "var(--green)",
    "HTTP (plain)": "#ff8a3d", "TCP": "var(--fg-dim)", "UDP": "var(--fg-dim)" };

  function connRow(c) {
    const protoClass = c.protocol === "TLS" ? "tls" : c.protocol === "DNS" ? "dns"
                     : c.protocol === "QUIC" ? "quic" : c.protocol === "HTTP" ? "http" : "";
    const isDom = !!c.domain && c.domain.includes(".") && /[a-z]/i.test(c.domain);
    const labelHtml = isDom
      ? `<a class="domain-link" href="https://${encodeURI(c.domain)}" target="_blank" rel="noopener">${esc(c.domain)}</a>`
      : `<span class="dev-name">${esc(c.domain || c.org || c.dst_ip)}</span>`;
    const sub = (!c.domain && c.org) ? ` <span class="cip">${esc(c.dst_ip)}</span>` : "";
    const alpn = c.alpn ? `<span class="alpn">${esc(c.alpn)}</span>` : "";
    const info = c.info ? `<div class="cinfo">${esc(c.info)}</div>` : "";
    return `<div class="conn-row">
      <span class="domain">${labelHtml} <span class="cport">:${c.port}</span>${sub}${info}</span>
      <span class="protocell"><span class="proto ${protoClass}">${esc(c.protocol || "TCP")}</span>${alpn}</span>
      <span class="updown">↑${kb(c.bytes_up || 0)} ↓${kb(c.bytes_down || 0)}</span>
      <span class="crate">${rate(c.rate)} · ${c.packets || 0}p</span>
    </div>`;
  }

  function protoMix(protocols) {
    const entries = Object.entries(protocols || {}).sort((a, b) => b[1] - a[1]);
    const total = entries.reduce((s, [, v]) => s + v, 0) || 1;
    const bar = entries.map(([k, v]) =>
      `<i style="width:${(v / total * 100).toFixed(1)}%;background:${PROTO_COLORS[k] || 'var(--muted)'}" title="${esc(k)} ${kb(v)}"></i>`).join("");
    const legend = entries.slice(0, 4).map(([k, v]) =>
      `<span><b style="color:${PROTO_COLORS[k] || 'var(--muted)'}">■</b> ${esc(k)} ${(v / total * 100).toFixed(0)}%</span>`).join("");
    return `<div class="pmix"><div class="pmix-bar">${bar}</div><div class="pmix-legend">${legend}</div></div>`;
  }

  function dgRow(k, v, mono) {
    return `<div class="dg-row"><span class="dg-k">${k}</span><span class="dg-v ${mono ? "mono" : ""}">${esc(v)}</span></div>`;
  }

  function deviceGroup(m, name) {
    const conns = (m.connections || []).slice(0, 18);
    const act = m.activity || "idle";
    const who = name
      ? `<b class="dg-name">${esc(name)}</b> <span class="dg-ip">${esc(m.ip)}</span>`
      : `<span class="dg-ip">${esc(m.ip)}</span>`;
    const extra = (m.user_agent ? dgRow("Client", m.user_agent) : "")
                + (m.ja3 ? dgRow("JA3 fingerprint", m.ja3, true) : "");
    return `<div class="dev-group">
      <div class="dg-head">
        <span class="who">${who}</span>
        <span class="act act-${act}">${act}</span>
      </div>
      <div class="dg-stats">
        <div><span class="s-k">▼ download</span><span class="s-v">${kb(m.total_down || 0)}</span><span class="s-r">${rate(m.rate_down)}</span></div>
        <div><span class="s-k">▲ upload</span><span class="s-v">${kb(m.total_up || 0)}</span><span class="s-r">${rate(m.rate_up)}</span></div>
        <div><span class="s-k">destinations</span><span class="s-v">${m.total_conns}</span></div>
        <div><span class="s-k">session</span><span class="s-v">${m.duration || 0}s</span></div>
      </div>
      ${protoMix(m.protocols)}
      ${extra}
      <div class="conn-list">
        ${conns.map(connRow).join("") || '<div class="conn-row"><span class="domain" style="color:var(--muted)">listening…</span></div>'}
      </div>
    </div>`;
  }

  function renderActivity(s) {
    const obs = s.observer || [];
    const has = obs.length > 0;
    $("#ap-dev-count").textContent = `${obs.length} devices`;
    // Only build the board that's actually on screen — the two boards share the
    // same feed, so rendering both every tick was double work.
    const view = (document.querySelector(".view.active") || {}).id || "view-lan";
    if (view !== "view-lan" && view !== "view-ap") return;
    const nameByIp = {}, nameByMac = {};
    (s.devices || []).forEach((d) => { if (d.name) { nameByIp[d.ip] = d.name; nameByMac[d.mac] = d.name; } });
    const nameOf = (m) => nameByIp[m.ip] || nameByMac[m.mac] || "";
    const html = has ? obs.map((m) => deviceGroup(m, nameOf(m))).join("") : "";
    if (view === "view-lan") {
      $("#activity").innerHTML = html;
      $("#act-empty").style.display = has ? "none" : "flex";
    } else {
      $("#ap-board").innerHTML = html;
      $("#ap-empty").style.display = has ? "none" : "flex";
    }
  }

  // ------------------------------------------------------------- render: AP + rail
  function renderAP(s) {
    const ap = s.ap || {};
    const stEl = $("#ap-state");
    stEl.textContent = ap.state || "off";
    stEl.className = "v " + (ap.state === "on" ? "on" : "off");
    $("#ap-clients").textContent = ap.client_count ?? 0;
    const errBox = $("#ap-error");
    errBox.innerHTML = (!ap.available && ap.detail)
      ? `<div class="banner-error">${esc(ap.detail)}</div>` : "";
    if (ap.ssid && !$("#ap-ssid").value) $("#ap-ssid").value = ap.ssid;
  }

  function renderRail(s) {
    const jam = s.jamming || {};
    const jamN = Object.keys(jam).length;
    const routedN = Object.values(jam).filter((m) => m === "route").length;
    $("#st-jam").textContent = jamN;
    $("#st-routed").textContent = routedN;
    armStop(jamN > 0 || (s.ap && s.ap.state === "on"));

    // rate spark from total observed bytes delta
    const total = (s.observer || []).reduce((a, m) => a + (m.total_bytes || 0), 0);
    if (lastBytes !== null) {
      rateHist.push(Math.max(0, total - lastBytes));
      if (rateHist.length > 44) rateHist.shift();
    }
    lastBytes = total;
    const max = Math.max(1, ...rateHist);
    $("#spark").innerHTML = rateHist.map((v) =>
      `<i style="height:${Math.max(2, (v / max) * 20)}px"></i>`).join("");

    if (s.log && s.log.length) {
      const last = s.log[s.log.length - 1];
      if (last) toast(`${last.action} ${last.target || last.ssid || last.note || ""}`.trim());
    }
  }

  function armStop(armed) {
    const btn = $("#stop-all");
    if (armed && !stopPulse && G) {
      stopPulse = G.to(btn, { color: "#ffd0da", duration: 1.2, repeat: -1, yoyo: true, ease: "sine.inOut" });
    } else if (!armed && stopPulse) {
      stopPulse.kill(); stopPulse = null; btn.style.color = "";
    }
  }

  // ------------------------------------------------------------- analytics
  function trackBandwidth(s) {
    const down = (s.observer || []).reduce((a, m) => a + (m.total_down || 0), 0);
    const up = (s.observer || []).reduce((a, m) => a + (m.total_up || 0), 0);
    const now = Date.now();
    if (lastBw.d !== null && down >= lastBw.d && up >= lastBw.u) {
      const dt = Math.max(0.5, (now - lastBw.t) / 1000);
      bwHist.push({ d: (down - lastBw.d) / dt, u: (up - lastBw.u) / dt });
      if (bwHist.length > 90) bwHist.shift();
    }
    lastBw = { d: down, u: up, t: now };
  }

  function svgLine(hist, w, h) {
    const pad = 5, n = hist.length;
    const maxv = Math.max(1, ...hist.map((p) => Math.max(p.d, p.u)));
    const xx = (i) => pad + (n <= 1 ? 0 : (i / (n - 1)) * (w - 2 * pad));
    const yy = (v) => h - pad - (v / maxv) * (h - 2 * pad);
    const path = (key) => hist.map((p, i) => `${i ? "L" : "M"}${xx(i).toFixed(1)} ${yy(p[key]).toFixed(1)}`).join(" ");
    const area = `${path("d")} L${xx(n - 1).toFixed(1)} ${h - pad} L${xx(0).toFixed(1)} ${h - pad} Z`;
    return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" height="${h}">
      <line x1="0" y1="${h - pad}" x2="${w}" y2="${h - pad}" stroke="rgba(255,255,255,.05)"/>
      <path d="${area}" fill="rgba(242,182,165,0.12)"/>
      <path d="${path("d")}" fill="none" stroke="var(--peach)" stroke-width="1.8"/>
      <path d="${path("u")}" fill="none" stroke="var(--lav)" stroke-width="1.4" opacity="0.8"/>
    </svg>`;
  }

  function svgDonut(protocols) {
    const entries = Object.entries(protocols).sort((a, b) => b[1] - a[1]);
    const total = entries.reduce((s, [, v]) => s + v, 0) || 1;
    const R = 58, r = 34, cx = 66, cy = 66; let a0 = -Math.PI / 2;
    const seg = entries.map(([k, v]) => {
      const frac = v / total, a1 = a0 + Math.max(0.0001, frac) * 2 * Math.PI, large = frac > 0.5 ? 1 : 0;
      const x0 = cx + R * Math.cos(a0), y0 = cy + R * Math.sin(a0);
      const x1 = cx + R * Math.cos(a1), y1 = cy + R * Math.sin(a1);
      const xi0 = cx + r * Math.cos(a1), yi0 = cy + r * Math.sin(a1);
      const xi1 = cx + r * Math.cos(a0), yi1 = cy + r * Math.sin(a0);
      a0 = a1;
      return `<path d="M${x0.toFixed(1)} ${y0.toFixed(1)} A${R} ${R} 0 ${large} 1 ${x1.toFixed(1)} ${y1.toFixed(1)} L${xi0.toFixed(1)} ${yi0.toFixed(1)} A${r} ${r} 0 ${large} 0 ${xi1.toFixed(1)} ${yi1.toFixed(1)} Z" fill="${PROTO_COLORS[k] || 'var(--muted)'}" opacity="0.85"/>`;
    }).join("");
    const legend = entries.slice(0, 6).map(([k, v]) =>
      `<span><b style="background:${PROTO_COLORS[k] || 'var(--muted)'}"></b>${esc(k)} ${(v / total * 100).toFixed(0)}% · ${kb(v)}</span>`).join("");
    return `<div class="donut-wrap"><svg width="132" height="132" viewBox="0 0 132 132">${seg}</svg><div class="donut-legend">${legend}</div></div>`;
  }

  function renderAnalytics(s) {
    if (!$("#view-analytics")) return;
    const devs = s.devices || [], obs = s.observer || [], c = s.context || {};
    const online = devs.filter((d) => d.online).length;
    const named = devs.filter((d) => d.name && d.kind !== "self").length;
    const conns = obs.reduce((a, m) => a + (m.total_conns || 0), 0);
    const down = obs.reduce((a, m) => a + (m.total_down || 0), 0);
    const up = obs.reduce((a, m) => a + (m.total_up || 0), 0);
    const jam = s.jamming || {};
    const gw = devs.find((d) => d.kind === "gateway");
    const nowRate = bwHist.length ? bwHist[bwHist.length - 1] : { d: 0, u: 0 };
    const kpis = [
      { k: "Devices online", v: `${online}<small>/${devs.length}</small>`, sub: "on " + (c.cidr || "—") },
      { k: "Named devices", v: named, sub: "identified" },
      { k: "Router", v: (gw && gw.name) || "Gateway", sub: (c.gateway_ip || "—") + (gw && gw.vendor ? " · " + gw.vendor : "") },
      { k: "Active connections", v: conns, sub: obs.length + " observed", accent: true },
      { k: "Traffic", v: kb(down + up), sub: `▼ ${kb(down)}  ▲ ${kb(up)}` },
      { k: "Bandwidth now", v: rate(nowRate.d) || "—", sub: `▲ ${rate(nowRate.u)}`, accent: true },
      { k: "AP clients", v: (s.ap && s.ap.state === "on") ? (s.ap.client_count || 0) : "—", sub: (s.ap && s.ap.state) || "—" },
      { k: "Jamming", v: Object.keys(jam).length, sub: "active ARP" },
    ];
    $("#kpi-row").innerHTML = kpis.map((x) =>
      `<div class="kpi ${x.accent ? "accent" : ""}"><span class="k">${x.k}</span><span class="v">${x.v}</span><span class="sub">${esc(String(x.sub || ""))}</span></div>`).join("");

    $("#sig-now").textContent = `▼ ${rate(nowRate.d)}  ▲ ${rate(nowRate.u)}`;
    $("#signal-chart").innerHTML = bwHist.length > 1 ? svgLine(bwHist, 600, 150)
      : '<div class="empty" style="height:150px"><div class="sub">collecting samples… route a device or start the Test-AP</div></div>';

    const protos = {};
    obs.forEach((m) => Object.entries(m.protocols || {}).forEach(([k, v]) => (protos[k] = (protos[k] || 0) + v)));
    $("#proto-donut").innerHTML = Object.keys(protos).length ? svgDonut(protos)
      : '<div class="empty" style="height:150px"><div class="sub">no traffic observed yet</div></div>';

    const nameFor = (m) => { const d = devs.find((z) => z.ip === m.ip || z.mac === m.mac); return (d && d.name) || m.ip; };
    const top = obs.filter((m) => m.total_bytes > 0).sort((a, b) => b.total_bytes - a.total_bytes).slice(0, 7);
    const tmax = Math.max(1, ...top.map((m) => m.total_bytes));
    $("#top-talkers").innerHTML = top.length ? top.map((m) =>
      `<div class="bar-row"><span class="bl">${esc(nameFor(m))}</span><span class="bt"><i style="width:${(m.total_bytes / tmax * 100).toFixed(1)}%"></i></span><span class="bv">${kb(m.total_bytes)}</span></div>`).join("")
      : '<div class="empty" style="height:120px"><div class="sub">no routed/observed traffic yet</div></div>';

    const known = devs.filter((d) => d.name);
    $("#known-count").textContent = known.length;
    $("#named-devices").innerHTML = known.length ? known.map((d) => {
      const tag = d.kind === "self" ? '<span class="ntag">YOU</span>' : d.kind === "gateway" ? '<span class="ntag">ROUTER</span>' : "";
      return `<div class="named-row"><span class="nn">${esc(d.name)}${tag}<span class="ni">${esc(d.ip)}</span></span><span class="nv">${esc(d.vendor || "")}</span></div>`;
    }).join("") : '<div class="empty" style="height:120px"><div class="sub">no named devices yet — try Identify</div></div>';
  }

  // ------------------------------------------------------------- main render
  function render(s) {
    if (!s) return;
    renderContext(s);
    renderEngineError(s);
    renderPreflight(s);
    renderDevices(s);
    renderActivity(s);
    renderAP(s);
    renderRail(s);
    trackBandwidth(s);
    renderAnalytics(s);
    $("#gate").style.display = s.consent ? "none" : "flex";
  }

  // ------------------------------------------------------------- live feed
  function connectWS() {
    let ws;
    try { ws = new WebSocket(`ws://${location.host}/api/ws`); } catch { return poll(); }
    ws.onmessage = (ev) => { try { render(JSON.parse(ev.data)); } catch {} };
    ws.onclose = () => setTimeout(connectWS, 1500);
    ws.onerror = () => { try { ws.close(); } catch {} };
  }
  function poll() { api("/state").then(render).finally(() => setTimeout(poll, 2000)); }

  // ------------------------------------------------------------- events
  function wire() {
    // consent
    $("#consent-accept").addEventListener("click", async () => {
      const note = $("#consent-note").value || "";
      const r = await post("/consent", { note });
      if (r.error) return toast(r.error, true);
      if (G) G.to($("#gate"), { opacity: 0, duration: 0.4, onComplete: () => ($("#gate").style.display = "none") });
      refresh();
    });

    // collapse everything to just the eye
    $("#eye-toggle").addEventListener("click", () => document.body.classList.toggle("eye-only"));

    // prerequisite downloader (Npcap)
    $("#preflight-bar").addEventListener("click", async (e) => {
      const inst = e.target.closest("[data-pf-install]");
      const open = e.target.closest("[data-pf-open]");
      if (inst) {
        const key = inst.dataset.pfInstall;
        inst.disabled = true;
        toast(`Downloading the official ${key} installer…`);
        const r = await post("/preflight/install", { key });
        if (r.error) {
          inst.disabled = false;
          toast(`${r.error}${r.page ? " — opening the download page instead" : ""}`, true);
          if (r.page) await post("/preflight/open", { key });
          return;
        }
        toast(`${key} installer launched — complete it, then click Re-check`);
      } else if (open) {
        await post("/preflight/open", { key: open.dataset.pfOpen });
        toast("Opened the official download page in your browser");
      } else if (e.target.closest("#pf-recheck")) {
        toast("Re-checking prerequisites…");
        await api("/preflight");
        refresh();
      }
    });

    // tabs
    document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
      t.classList.add("active");
      const view = t.dataset.view;
      document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
      const el = $("#view-" + view);
      el.classList.add("active");
      if (G) G.fromTo(el, { opacity: 0, y: 10 }, { opacity: 1, y: 0, duration: 0.32, ease: "power2.out" });
    }));

    // STOP · restore all
    $("#stop-all").addEventListener("click", async () => {
      await post("/stop_all");
      toast("restore-all issued — all targets returned to normal");
      refresh();
    });

    $("#rescan").addEventListener("click", async () => { toast("sweeping subnet…"); await post("/scan"); refresh(); });

    // Identify: passive DHCP + UPnP name discovery (no routing / MITM)
    $("#identify").addEventListener("click", async () => {
      const btn = $("#identify");
      const orig = btn.textContent;
      btn.disabled = true;
      btn.textContent = "Listening…";
      toast("Identify running ~25s — toggle a device's WiFi off→on to catch its name (no traffic is routed)");
      const r = await post("/identify?seconds=25");
      btn.disabled = false;
      btn.textContent = orig;
      if (r.error) return toast(r.error, true);
      toast(`Identify done — UPnP ${r.ssdp} · DHCP ${r.dhcp} · named ${r.named}`);
      refresh();
    });

    // device controls (delegated)
    $("#dev-rows").addEventListener("click", async (e) => {
      const btn = e.target.closest("button[data-act]");
      if (!btn) return;
      const { act, mac, ip } = btn.dataset;
      btn.disabled = true;
      if (act === "restore") {
        await post("/unjam", { ip, mac });
        toast(`${ip} restored`);
      } else {
        const allow = await post("/allow", { ip, mac });
        if (allow.error) { btn.disabled = false; return toast(allow.error, true); }
        const r = await post("/jam", { ip, mac, mode: act === "block" ? "cut" : "route" });
        if (r.error) { btn.disabled = false; return toast(r.error, true); }
        toast(`${ip} → ${act === "block" ? "cut" : "routed"}`);
      }
      refresh();
    });

    // AP
    $("#ap-apply").addEventListener("click", async () => {
      const ssid = $("#ap-ssid").value.trim();
      const passphrase = $("#ap-pass").value;
      if (!ssid || passphrase.length < 8) return toast("SSID required; passphrase ≥ 8 chars", true);
      toast("configuring hotspot…");
      const cfg = await post("/ap/configure", { ssid, passphrase });
      if (cfg.error) return toast(cfg.error, true);
      const r = await post("/ap/start");
      if (r.error) return toast(r.error, true);
      toast(`Test-AP '${ssid}' started`);
      refresh();
    });
    $("#ap-stop").addEventListener("click", async () => { await post("/ap/stop"); toast("Test-AP stopped"); refresh(); });

    // clear the captured destination log (any active routing stays on)
    const clearLog = async (msg) => { await post("/observer/clear"); toast(msg); refresh(); };
    $("#clear-activity").addEventListener("click", () => clearLog("destination log cleared"));
    $("#clear-ap").addEventListener("click", () => clearLog("metadata board cleared"));
  }

  const refresh = () => api("/state").then(render);

  // ------------------------------------------------------------- boot
  wire();
  refresh();
  connectWS();
})();
