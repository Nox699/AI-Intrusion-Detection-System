/* No secrets, external requests or dynamic HTML from log values. */
"use strict";
(() => {
  const nav = document.getElementById("sidebar");
  const toggle = document.getElementById("nav-toggle");
  const scrim = document.getElementById("nav-scrim");
  const setNav = (open) => {
    if (!nav || !toggle || !scrim) return;
    nav.classList.toggle("open", open);
    toggle.setAttribute("aria-expanded", String(open));
    toggle.setAttribute("aria-label", open ? "Luk navigation" : "Åbn navigation");
    scrim.hidden = !open;
  };
  toggle?.addEventListener("click", () => setNav(!nav.classList.contains("open")));
  scrim?.addEventListener("click", () => setNav(false));
  document.addEventListener("keydown", (event) => { if (event.key === "Escape") setNav(false); });
  document.querySelectorAll(".refresh-page").forEach(button => button.addEventListener("click", () => window.location.reload()));

  const chart = document.getElementById("activity-chart");
  if (!chart) return;
  const zone = document.body.dataset.timezone || "Europe/Copenhagen";
  const interval = Math.max(3, Number(document.body.dataset.poll) || 5) * 1000;
  const hours = Number(chart.dataset.hours) || 24;
  const error = document.getElementById("connection-error");
  const errorMessage = document.getElementById("connection-message");
  const timeFormat = new Intl.DateTimeFormat("da-DK", { timeZone: zone, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const fullFormat = new Intl.DateTimeFormat("da-DK", { timeZone: zone, day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const shortFormat = new Intl.DateTimeFormat("da-DK", { timeZone: zone, hour: "2-digit", minute: "2-digit" });
  const dayFormat = new Intl.DateTimeFormat("da-DK", { timeZone: zone, day: "2-digit", month: "2-digit" });
  const numberFormat = new Intl.NumberFormat("da-DK");
  let fetching = false;
  let firstChart = true;
  let seriesSignature = "";
  let timer = null;
  let authExpired = false;

  function date(value, formatter = fullFormat) {
    if (typeof value !== "number" || !Number.isFinite(value)) return "—";
    return formatter.format(new Date(value * 1000));
  }
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = String(text);
    return node;
  }
  function renderAlerts(alerts) {
    const target = document.getElementById("recent-alerts");
    if (!target) return;
    const container = el("div", "alert-list");
    if (!alerts.length) {
      const empty = el("div", "empty-state");
      empty.append(el("h3", "", "Ingen alarmforløb i perioden"), el("p", "", "Der er ingen registrerede alarmer i det valgte tidsrum. Kontrollér også datakildens status."));
      target.replaceChildren(empty);
      return;
    }
    const severities = { critical: "Kritisk", high: "Høj", medium: "Mellem", low: "Lav", info: "Info" };
    for (const item of alerts) {
      if (!Number.isSafeInteger(Number(item.id)) || Number(item.id) < 1) continue;
      const row = el("a", "alert-list-item");
      row.href = `/alerts/${Number(item.id)}`;
      const high = ["critical", "high"].includes(item.severity);
      row.append(el("span", `alert-symbol ${high ? "danger" : "warning"}`, "!"));
      const summary = el("div", "alert-summary");
      summary.append(el("strong", "", item.title), el("span", "", `${item.source_ip} · ${date(item.last_seen)}`));
      row.append(summary);
      const sev = Object.hasOwn(severities, item.severity) ? item.severity : "info";
      row.append(el("span", `badge severity-${sev}`, severities[sev]), el("span", "muted", "→"));
      container.append(row);
    }
    target.replaceChildren(container);
  }
  function renderChart(series, serverTime) {
    if (!window.Plotly) throw new Error("Grafbiblioteket kunne ikke indlæses.");
    const compact = chart.clientWidth < 560;
    const signature = `${JSON.stringify(series)}:${Math.floor(serverTime / 60)}:${compact}`;
    if (signature === seriesSignature && !firstChart) return;
    const rows = series.filter(row => Number.isFinite(row.timestamp) && Number.isFinite(row.success) && Number.isFinite(row.failure) && Number.isFinite(row.preauth))
      .sort((a, b) => a.timestamp - b.timestamp);
    const bucketSeconds = hours <= 24 ? 300 : 3600;
    const end = serverTime;
    const start = end - hours * 3600;
    // Show only observed buckets. An absent bucket is not evidence that
    // collection was operating, so it must not become a synthetic zero.
    // Clip partial first/current buckets to the actual selected time window.
    const plotRows = rows.map(row => ({ ...row,
      left: Math.max(start, row.timestamp), right: Math.min(end, row.timestamp + bucketSeconds)
    })).filter(row => row.right > row.left);
    const showDates = hours >= 24 || dayFormat.format(new Date(start * 1000)) !== dayFormat.format(new Date(end * 1000));
    const tickCount = compact ? 3 : 7;
    const ticks = Array.from({ length: tickCount }, (_value, index) => start + (end - start) * index / (tickCount - 1));
    const intervalLabel = (timestamp) => `${date(timestamp, dayFormat)} ${date(timestamp, timeFormat)}`;
    // A missing time bucket does not prove that monitoring was continuous.
    // Put a null point between non-adjacent observed buckets. Plotly then
    // breaks each curve instead of drawing a misleading line across the gap.
    const points = [];
    let previous = null;
    for (const row of plotRows) {
      if (previous && row.left - previous.right > 1) {
        points.push({ x: (previous.right + row.left) * 500,
          label: null, success: null, failure: null, preauth: null });
      }
      points.push({ x: (row.left + row.right) * 500,
        label: `${intervalLabel(row.left)}–${intervalLabel(row.right)}`,
        success: row.success, failure: row.failure, preauth: row.preauth });
      previous = row;
    }
    const x = points.map(point => point.x);
    const hover = points.map(point => point.label);
    const maxCount = Math.max(0, ...plotRows.flatMap(row => [row.success, row.failure, row.preauth]));
    // Counts remain measured per bucket. Straight segments are visual guides,
    // not interpolated measurements, and missing buckets stay unconnected.
    const base = { type: "scatter", mode: "lines+markers", connectgaps: false,
      x, customdata: hover,
      hovertemplate: "%{customdata}<br>%{y} registrerede hændelser<extra>%{fullData.name}</extra>" };
    const traces = [
      { ...base, name: "Vellykkede", y: points.map(point => point.success),
        line: { color: "#68d8b6", width: 2.5, shape: "linear" },
        marker: { color: "#68d8b6", size: 7 } },
      { ...base, name: "Fejlede", y: points.map(point => point.failure),
        line: { color: "#ef6b6b", width: 2.5, shape: "linear" },
        marker: { color: "#ef6b6b", size: 7 } },
      { ...base, name: "Afbrud før login", y: points.map(point => point.preauth),
        line: { color: "#e8ad70", width: 2.5, shape: "linear" },
        marker: { color: "#e8ad70", size: 7 } }
    ];
    const layout = {
      paper_bgcolor: "transparent", plot_bgcolor: "transparent",
      font: { family: '"Segoe UI",Arial,sans-serif', color: "#8797ad", size: 10 },
      margin: { l: 46, r: 24, t: 15, b: showDates ? 56 : 38 }, showlegend: false,
      hovermode: "closest", uirevision: "ssh-activity-lines", dragmode: false,
      xaxis: { type: "linear", range: [start * 1000, end * 1000], tickmode: "array", tickvals: ticks.map(value => value * 1000),
        ticktext: ticks.map(value => `${date(value, shortFormat)}${showDates ? `<br>${date(value, dayFormat)}` : ""}`),
        showgrid: false, zeroline: false, fixedrange: true, ticks: "", ticklabelstandoff: 6, tickfont: { size: 11 } },
      yaxis: { rangemode: "tozero", gridcolor: "#233040", zerolinecolor: "#28394b", fixedrange: true,
        nticks: 5, dtick: maxCount <= 5 ? 1 : undefined, tickformat: ",d", tickfont: { size: 11 }, minallowed: 0 },
      hoverlabel: { bgcolor: "#1b293b", bordercolor: "#3a526b", font: { color: "#e1ebf6", size: 11 } },
      annotations: plotRows.length ? [] : [{ text: "Ingen hændelser i perioden", showarrow: false, xref: "paper", yref: "paper", x: 0.5, y: 0.5, font: { color: "#8b9db4", size: 12 } }]
    };
    if (firstChart) chart.replaceChildren();
    window.Plotly.react(chart, traces, layout, { responsive: true, displayModeBar: false, scrollZoom: false, staticPlot: false });
    firstChart = false;
    seriesSignature = signature;
  }
  function setStatus(status) {
    const badge = document.getElementById("collector-badge");
    const label = document.getElementById("collector-label");
    const tones = ["good", "warning", "danger", "info"];
    if (badge && label) {
      badge.classList.remove(...tones);
      badge.classList.add(tones.includes(status.collector_tone) ? status.collector_tone : "warning");
      label.textContent = status.collector_label;
    }
    const model = document.getElementById("model-status");
    if (model) {
      model.classList.remove(...tones);
      model.classList.add(tones.includes(status.model_tone) ? status.model_tone : "warning");
      model.textContent = status.model_label;
    }
    function notice(id, title, message, tone) {
      let node = document.getElementById(id);
      if (!message) {
        if (node) node.hidden = true;
        return;
      }
      if (!node) {
        node = el("div", `notice ${tone}`);
        node.id = id;
        const body = el("div");
        body.append(el("strong"), el("span"));
        node.append(body);
        const main = document.getElementById("main");
        main.insertBefore(node, main.querySelector(".page-heading"));
      }
      node.classList.remove("danger", "warning", "info", "good");
      node.classList.add(tone);
      node.querySelector("strong").textContent = title;
      node.querySelector("div > span").textContent = message;
      node.hidden = false;
    }
    const badCollector = ["error", "stale", "stopped", "unknown"].includes(status.collector_state);
    notice("collector-notice", status.collector_label,
      badCollector ? (status.collector?.message || "Historikken kan læses, men løbende indsamling er ikke bekræftet. Se systemstatus.") : "",
      status.collector_tone || "warning");
    notice("data-gap-notice", "Muligt hul i datagrundlaget", status.data_gap?.message, "warning");
    notice("analysis-error-notice", "Der er registreret en analysefejl", status.analysis_error?.message, "danger");
    notice("data-quality-notice", "Datakvaliteten kræver opmærksomhed", status.data_quality?.message, "warning");
  }
  async function refresh() {
    if (fetching || authExpired || document.hidden) return;
    fetching = true;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), Math.max(8000, interval));
    try {
      const response = await fetch(`/api/overview?hours=${hours}`, { credentials: "same-origin", cache: "no-store", signal: controller.signal, headers: { Accept: "application/json" } });
      if (response.status === 401) {
        authExpired = true;
        throw new Error("Din session er udløbet. Opdatér siden for at logge ind igen.");
      }
      if (!response.ok) throw new Error("Data kan ikke læses lige nu. De viste tal kan være forældede.");
      const payload = await response.json();
      for (const key of ["events", "success", "failure", "alerts"]) {
        const metric = document.getElementById(`metric-${key}`);
        if (metric) metric.textContent = numberFormat.format(payload.data.totals[key]);
      }
      const preauth = document.getElementById("metric-preauth");
      if (preauth) preauth.textContent = numberFormat.format(payload.data.preauth_count);
      document.getElementById("last-event").textContent = date(payload.data.last_event_at);
      document.getElementById("last-update").textContent = `Opdateret ${date(payload.server_time, timeFormat)}`;
      renderAlerts(payload.data.recent_alerts || []);
      setStatus(payload.status);
      renderChart(payload.data.series || [], payload.server_time);
      error.hidden = true;
    } catch (problem) {
      error.hidden = false;
      errorMessage.textContent = problem.name === "AbortError" ? "Serveren svarede ikke i tide. De viste data kan være forældede." : problem.message;
    } finally {
      clearTimeout(timeout);
      fetching = false;
      if (!authExpired) timer = setTimeout(refresh, interval);
    }
  }
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) { clearTimeout(timer); refresh(); }
  });
  window.addEventListener("pagehide", () => clearTimeout(timer), { once: true });
  refresh();
})();
