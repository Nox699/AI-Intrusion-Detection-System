"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const nav = require("../src/yggdrasil_ids/static/nav_alerts.js");
const stamp = 1800000000;
const data = cases => nav.validate({ meaning: "browser_unseen_alert_revisions_v1", period_hours: 24,
  instance: "a".repeat(32), cases });
const item = (id, section = "sudo", count = 1) => ({ id, section, count, last_seen: stamp });

test("opening sudo clears both sudo and global warnings for the same case", () => {
  const snapshot = data([item(4)]);
  assert.equal(nav.counts(snapshot, {}).sudo, 1);
  const seen = nav.acknowledge(snapshot, {}, "sudo");
  assert.equal(nav.counts(snapshot, seen).sudo, 0);
  assert.equal(nav.counts(snapshot, seen).alerts, 0);
});

test("visiting one section leaves unrelated alarm types unseen", () => {
  const snapshot = data([item(4), item(5, "network"), item(6, "ssh")]);
  const seen = nav.acknowledge(snapshot, {}, "sudo");
  assert.equal(nav.counts(snapshot, seen).alerts, 2);
  assert.equal(nav.counts(snapshot, seen).network, 1);
  assert.equal(nav.counts(snapshot, seen).ssh, 1);
});

test("alarm detail acknowledges only that case; alarm overview acknowledges all", () => {
  const snapshot = data([item(4), item(5)]);
  const seen = nav.acknowledge(snapshot, {}, "detail", 4);
  assert.equal(nav.counts(snapshot, seen).alerts, 1);
  assert.equal(nav.counts(snapshot, nav.acknowledge(snapshot, seen, "alerts")).alerts, 0);
});

test("new cases and updates to older cases restore the warning", () => {
  const first = data([item(4), item(8)]);
  const seen = nav.acknowledge(first, {}, "sudo");
  const next = data([item(4, "sudo", 2), item(8), item(9, "network")]);
  assert.equal(nav.counts(next, seen).sudo, 1);
  assert.equal(nav.counts(next, seen).alerts, 2);
});

test("polling must not acknowledge alerts arriving after the rendered snapshot", () => {
  const rendered = data([item(4)]);
  const seen = nav.acknowledge(rendered, {}, "sudo");
  assert.equal(nav.counts(data([item(4), item(5)]), seen).sudo, 1);
});

test("expiry and stale pages do not turn previously seen cases into new alerts", () => {
  const updated = data([item(4, "sudo", 2), item(5)]);
  const seen = nav.acknowledge(updated, {}, "sudo");
  const merged = nav.acknowledge(data([item(4)]), seen, "sudo");
  assert.equal(merged[4].count, 2);
  assert.equal(nav.counts(data([item(4, "sudo", 2)]), merged).alerts, 0);
});

test("browser marks survive serialization and expire separately from alert history", () => {
  const now = 1800000000000;
  const seen = nav.acknowledge(data([item(4)]), {}, "sudo", null, now);
  const raw = JSON.stringify({ version: 1, seen });
  assert.equal(nav.counts(data([item(4)]), nav.decode(raw, now + 1000)).sudo, 0);
  assert.equal(Object.keys(nav.decode(raw, now + 49 * 3600000)).length, 0);
  assert.notEqual(nav.key("a".repeat(32)), nav.key("b".repeat(32)));
});

test("invalid API and storage values cannot invent read cases", () => {
  assert.throws(() => data([item(4), item(4)]));
  assert.throws(() => data([{ ...item(4), count: -1 }]));
  assert.throws(() => data([{ ...item(4), section: "<script>" }]));
  assert.equal(Object.keys(nav.decode("invalid")).length, 0);
  assert.equal(Object.keys(nav.decode('{"version":1,"seen":{"__proto__":{"count":1}}}')).length, 0);
});

test("failed polls preserve warnings and do not auto-read new arrivals on an open page", async () => {
  let fail = false;
  const intervals = [];
  const stored = new Map();
  const marker = { hidden: true };
  const link = { dataset: { alertSection: "sudo" }, setAttribute() {}, removeAttribute() {},
    querySelector: selector => selector === ".nav-warning" ? marker : { textContent: "Sudo" } };
  const doc = { hidden: false, querySelectorAll: () => [link], addEventListener() {},
    getElementById: () => ({ textContent: JSON.stringify({ snapshot: data([item(4)]), scope: "sudo" }) }) };
  const storage = { getItem: key => stored.get(key) ?? null, setItem: (key, value) => stored.set(key, value) };
  const win = { localStorage: storage, sessionStorage: storage, AbortController,
    setTimeout, clearTimeout, setInterval: fn => { intervals.push(fn); return 1; },
    clearInterval() {}, addEventListener() {},
    fetch: async () => { if (fail) throw Error("offline"); return { ok: true, json: async () => data([item(4), item(5)]) }; } };
  nav.start(doc, win);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(marker.hidden, false); // Case 5 was never part of the rendered page.
  fail = true;
  await intervals[0]();
  assert.equal(marker.hidden, false);
  // A successful reload acknowledges the updated rendered page in the same browser.
  doc.getElementById = () => ({ textContent: JSON.stringify({ snapshot: data([item(4), item(5)]), scope: "sudo" }) });
  nav.start(doc, win);
  assert.equal(marker.hidden, true);
});
