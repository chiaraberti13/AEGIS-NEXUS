"use strict";

// Operator audit-log view as its own ES module (Cycle I, ADR 0003).
// Read-only: imports only from the leaf module core.js, calls no orchestrator,
// so it carries no import cycle and needs no injected hook. All audit fields
// (operator-influenced target IDs and detail values) are rendered as text.
import { $, t, state, safeGet, formatDate } from "./core.js";

function auditTargetLabel(item) {
  const type = item.target_type || "";
  const id = item.target_id || "";
  if (type && id) return type + " · " + id;
  return type || id || "—";
}

function renderAuditRetention() {
  const node = $("audit-retention");
  if (!node) return;
  const info = state.auditRetention;
  if (!info) {
    node.textContent = "";
    return;
  }
  const count = String(info.count ?? state.auditItems.length);
  const rows = info.max_rows ? String(info.max_rows) : "∞";
  if (info.retention_days && Number(info.retention_days) > 0) {
    node.textContent = t("audit.retention")
      .replace("{days}", String(info.retention_days))
      .replace("{rows}", rows)
      .replace("{count}", count);
  } else {
    node.textContent = t("audit.retentionNoAge")
      .replace("{rows}", rows)
      .replace("{count}", count);
  }
}

export function renderAuditList() {
  const root = $("audit-list");
  if (!root) return;
  root.replaceChildren();
  const items = state.auditItems || [];
  $("audit-count").textContent = String(items.length);
  renderAuditRetention();
  if (!items.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 7;
    cell.className = "empty";
    // textContent keeps every operator-influenced field inert markup.
    cell.textContent = t("audit.empty");
    row.append(cell);
    root.append(row);
    return;
  }
  const outcomeKeys = {success: "audit.outcome.success", denied: "audit.outcome.denied", error: "audit.outcome.error"};
  items.forEach((item) => {
    const row = document.createElement("tr");
    const detail = item.detail && Object.keys(item.detail).length ? JSON.stringify(item.detail) : "—";
    const cells = [
      formatDate(item.timestamp),
      item.operator || "—",
      item.action || "—",
      auditTargetLabel(item),
      t(outcomeKeys[item.outcome] || "audit.outcome.success"),
      item.source_ip || "—",
      detail,
    ];
    cells.forEach((value, index) => {
      const cell = document.createElement("td");
      // All audit fields are rendered as text, never HTML: target IDs and
      // detail values can carry operator-supplied content.
      cell.textContent = String(value);
      if (index === 2 || index === 6) cell.className = "mono";
      row.append(cell);
    });
    root.append(row);
  });
}

function auditParams() {
  const params = new URLSearchParams();
  const operator = $("audit-filter-operator").value.trim();
  const action = $("audit-filter-action").value.trim();
  const targetType = $("audit-filter-target-type").value.trim();
  const targetId = $("audit-filter-target-id").value.trim();
  if (operator) params.set("operator", operator);
  if (action) params.set("action", action);
  if (targetType) params.set("target_type", targetType);
  if (targetId) params.set("target_id", targetId);
  params.set("limit", "500");
  return params;
}

export async function loadAudit() {
  const data = await safeGet("/api/v1/audit?" + auditParams().toString());
  if (!data) {
    state.auditItems = [];
    state.auditRetention = null;
    renderAuditList();
    return;
  }
  state.auditItems = data.items || [];
  state.auditRetention = {
    retention_days: data.retention_days,
    max_rows: data.max_rows,
    count: (data.items || []).length,
  };
  renderAuditList();
}
