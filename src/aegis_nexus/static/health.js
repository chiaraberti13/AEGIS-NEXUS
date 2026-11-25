"use strict";

// Platform health view as its own ES module (Cycle I, ADR 0003).
// Read-only: imports only from the leaf module core.js, calls no orchestrator,
// so it carries no import cycle and needs no injected hook.
import { $, t, safeGet, fact, formatDate } from "./core.js";

function formatBytes(value) {
  if (value === null || value === undefined) return "—";
  let n = Number(value);
  if (!isFinite(n)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
  return (i === 0 ? String(n) : n.toFixed(1)) + " " + units[i];
}

function healthPill(node, state) {
  const value = String(state || "unknown");
  node.className = "status-pill state-" + value;
  node.textContent = t("health.state." + value) || value;
}

export async function loadHealth() {
  const status = await safeGet("/api/v1/operations/status");
  const sensors = await safeGet("/api/v1/sensors/health");
  const collector = status?.collector || {};
  const storage = collector.storage || {};
  const counters = status?.counters || {};
  const schema = collector.database_schema || {};

  healthPill($("health-state"), collector.state);

  const storageRoot = $("health-storage");
  storageRoot.replaceChildren();
  fact(storageRoot, t("health.ready"), collector.ready ? t("common.yes") : t("common.no"));
  fact(storageRoot, t("health.dbSize"), formatBytes(storage.database_size_bytes));
  fact(storageRoot, t("health.events"), String(storage.event_count ?? "—") + " / " + String(storage.max_events ?? "—"));
  fact(storageRoot, t("health.capacity"),
    storage.capacity_used_fraction == null ? "—" : (Math.round(storage.capacity_used_fraction * 1000) / 10) + "%");
  fact(storageRoot, t("health.freeDisk"), formatBytes(collector.storage_free_bytes));
  fact(storageRoot, t("health.retention"), String(storage.retention_days ?? "—"));
  fact(storageRoot, t("health.schema"), String(schema.version ?? "—") + " / " + String(schema.latest_supported ?? "—"));

  const sensorRoot = $("health-sensors");
  sensorRoot.replaceChildren();
  const list = sensors?.sensors || [];
  if (!list.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = t("empty.noData");
    sensorRoot.append(empty);
  }
  list.forEach((sensor) => {
    const row = document.createElement("div");
    row.className = "health-sensor-item";
    const name = document.createElement("strong");
    name.textContent = String(sensor.sensor_id || "—");
    const badge = document.createElement("span");
    healthPill(badge, sensor.health);
    const meta = document.createElement("span");
    meta.className = "muted";
    meta.textContent = t("health.rate") + ": " + String(sensor.event_rate_per_hour ?? 0) + "/h · "
      + t("health.lastEvent") + ": " + formatDate(sensor.last_event_at);
    row.append(name, badge, meta);
    sensorRoot.append(row);
  });

  const counterRoot = $("health-counters");
  counterRoot.replaceChildren();
  fact(counterRoot, t("health.authFailures"), counters.sensor_auth_failures ?? 0);
  fact(counterRoot, t("health.replayRejections"), counters.sensor_replay_rejections ?? 0);
  fact(counterRoot, t("health.validationRejections"), counters.ingest_validation_rejections ?? 0);
  fact(counterRoot, t("health.loadShed"), counters.load_shed_events ?? 0);

  const evidenceRoot = $("health-evidence");
  evidenceRoot.replaceChildren();
  fact(evidenceRoot, t("health.sensorsSilent"), sensors?.silent_count ?? 0);
  const gaps = (sensors?.sensors || []).filter((s) => s.sequence_gaps).map((s) => s.sensor_id);
  fact(evidenceRoot, t("health.sequenceGaps"), gaps.length ? gaps : "—");
}
