/* Browser-local seen state. Only anonymous case revisions enter storage. */
"use strict";
((root, factory) => {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.YggdrasilNavAlerts = api;
})(globalThis, () => {
  const sections = ["ssh", "preauth", "network", "sudo", "alerts"];
  const ttl = 48 * 3600 * 1000;
  const safeTime = n => typeof n === "number" && Number.isFinite(n) && n > 0;
  const safeCount = n => Number.isSafeInteger(n) && n > 0;
  const key = instance => `yggdrasil-nav-seen-v1:${instance}`;

  function validate(data) {
    if (!data || data.meaning !== "browser_unseen_alert_revisions_v1" ||
        data.period_hours !== 24 || !/^[0-9a-f]{32}$/.test(data.instance) ||
        !Array.isArray(data.cases) || data.cases.length > 10000) throw Error("Invalid snapshot");
    const ids = new Set();
    for (const item of data.cases) {
      if (!safeCount(item.id) || !safeCount(item.count) || !safeTime(item.last_seen) ||
          ![...sections.slice(0, 4), "other"].includes(item.section) || ids.has(item.id)) {
        throw Error("Invalid case revision");
      }
      ids.add(item.id);
    }
    return data;
  }

  function decode(raw, now = Date.now()) {
    const seen = Object.create(null);
    try {
      const parsed = JSON.parse(raw);
      if (parsed?.version !== 1 || !parsed.seen || typeof parsed.seen !== "object") return seen;
      for (const [id, item] of Object.entries(parsed.seen).slice(0, 10000)) {
        if (/^[1-9][0-9]*$/.test(id) && Number.isSafeInteger(Number(id)) &&
            item && safeCount(item.count) && safeTime(item.last_seen) &&
            safeTime(item.marked_at) && now - ttl <= item.marked_at && item.marked_at <= now + 60000) {
          seen[id] = { count: item.count, last_seen: item.last_seen, marked_at: item.marked_at };
        }
      }
    } catch (_error) { /* Missing or damaged storage starts with unseen cases. */ }
    return seen;
  }

  const newer = (item, previous) => !previous || item.count > previous.count ||
    (item.count === previous.count && item.last_seen > previous.last_seen);

  function acknowledge(data, seen, scope, alertId = null, now = Date.now()) {
    const result = Object.assign(Object.create(null), seen);
    for (const item of data.cases) {
      if ((scope === "alerts" || item.section === scope || (scope === "detail" && item.id === alertId)) &&
          newer(item, result[item.id])) {
        result[item.id] = { count: item.count, last_seen: item.last_seen, marked_at: now };
      }
    }
    return result;
  }

  function counts(data, seen) {
    const result = Object.fromEntries(sections.map(section => [section, 0]));
    for (const item of data.cases) {
      if (!newer(item, seen[item.id])) continue;
      result.alerts += 1;
      if (Object.hasOwn(result, item.section)) result[item.section] += 1;
    }
    return result;
  }

  function start(doc, win) {
    const links = [...doc.querySelectorAll(".nav-link[data-alert-section]")]
      .filter(link => sections.includes(link.dataset.alertSection));
    if (!links.length) return;
    let current = null, memory = Object.create(null), busy = false, timer = null;
    const stores = [];
    for (const name of ["localStorage", "sessionStorage"]) {
      try { if (win[name]) stores.push(win[name]); } catch (_error) { /* Storage may be disabled. */ }
    }
    function readSeen() {
      let result = Object.assign(Object.create(null), memory);
      for (const storage of stores) {
        try {
          for (const [id, item] of Object.entries(decode(storage.getItem(key(current.instance))))) {
            if (newer(item, result[id])) result[id] = item;
          }
        } catch (_error) { /* Keep known state when browser storage is unavailable. */ }
      }
      return result;
    }
    function save(seen) {
      memory = Object.fromEntries(Object.entries(seen)
        .sort((a, b) => b[1].marked_at - a[1].marked_at).slice(0, 10000));
      const raw = JSON.stringify({ version: 1, seen: memory });
      for (const storage of stores) {
        try { storage.setItem(key(current.instance), raw); } catch (_error) { /* Use next store. */ }
      }
    }
    function render() {
      if (!current) return;
      const unseen = counts(current, readSeen());
      for (const link of links) {
        const count = unseen[link.dataset.alertSection];
        const marker = link.querySelector(".nav-warning");
        if (!marker) continue;
        marker.hidden = count === 0;
        if (count) {
          const label = link.querySelector("span")?.textContent || "";
          const detail = `${label}: ${count} ${count === 1 ? "ny eller opdateret alarm" : "nye eller opdaterede alarmer"}`;
          link.title = detail;
          link.setAttribute("aria-label", detail);
        } else {
          link.removeAttribute("title"); link.removeAttribute("aria-label");
        }
      }
    }
    try {
      const view = JSON.parse(doc.getElementById("nav-alert-view")?.textContent || "null");
      if (view?.snapshot) {
        current = validate(view.snapshot);
        // Acknowledge exactly the server-rendered revisions, once. Subsequent
        // polls on an open page must never silently acknowledge newer arrivals.
        save(acknowledge(current, readSeen(), view.scope, view.alert_id));
        render();
      }
    } catch (_error) { /* Do not invent a seen state from invalid HTML data. */ }

    async function refresh() {
      if (busy || doc.hidden) return;
      busy = true;
      const controller = new win.AbortController();
      const timeout = win.setTimeout(() => controller.abort(), 8000);
      try {
        const response = await win.fetch("/api/nav-alerts", { credentials: "same-origin",
          cache: "no-store", headers: { Accept: "application/json" }, signal: controller.signal });
        if (!response.ok) return;
        const next = validate(await response.json());
        if (current && next.instance !== current.instance) memory = Object.create(null);
        current = next;
        render();
      } catch (_error) { /* A failed poll never clears an existing warning. */ }
      finally { win.clearTimeout(timeout); busy = false; }
    }
    const resume = () => { if (timer === null) timer = win.setInterval(refresh, 15000); refresh(); };
    doc.addEventListener("visibilitychange", () => { if (!doc.hidden) refresh(); });
    win.addEventListener("storage", event => { if (current && event.key === key(current.instance)) render(); });
    win.addEventListener("pagehide", () => { win.clearInterval(timer); timer = null; });
    win.addEventListener("pageshow", () => resume());
    resume();
  }

  return { validate, decode, acknowledge, counts, key, start };
});
