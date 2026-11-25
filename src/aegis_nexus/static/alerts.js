"use strict";

// Alert triage view as its own ES module (Cycle I, ADR 0003).
// Imports only from the leaf module core.js. Its two cross-view dependencies —
// opening a referenced event in the investigate view, and seeding a new case
// from the selected alert — are inverted via injected hooks that app.js
// registers at bootstrap, so there is no import cycle.
import { $, t, state, safeGet, requestJSON, formatDate } from "./core.js";

let openEventInInvestigate = null;
export function setAlertEventOpener(fn) {
  openEventInInvestigate = fn;
}

let caseSeeder = null;
export function setCaseSeeder(fn) {
  caseSeeder = fn;
}

function renderAlertList() {
  const root = $("alert-list");
  if (!root) return;
  root.replaceChildren();
  $("alert-count").textContent = String(state.alerts.length);
  if (!state.alerts.length) {
    const empty = document.createElement("p");
    empty.className = "mini-empty";
    empty.textContent = t("alerts.empty");
    root.append(empty);
    return;
  }
  state.alerts.forEach((item) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "alert-list-item" + (state.selectedAlert?.id === item.id ? " selected" : "");
    const head = document.createElement("div");
    head.className = "alert-list-head";
    const title = document.createElement("strong");
    title.textContent = item.title;
    const severity = document.createElement("span");
    severity.className = "badge alert-severity " + String(item.severity || "info").toLowerCase();
    severity.textContent = String(item.severity || "info").toUpperCase();
    head.append(title, severity);
    const meta = document.createElement("span");
    meta.className = "alert-list-meta";
    meta.textContent = [item.rule_id + "@" + item.rule_version, item.source_ip || "—", t("alerts.status." + item.status)].join(" · ");
    const tail = document.createElement("span");
    tail.className = "alert-list-meta";
    tail.textContent = formatDate(item.last_seen) + " · " + t("alerts.occurrences") + ": " + String(item.occurrence_count || 1);
    button.append(head, meta, tail);
    button.addEventListener("click", () => selectAlert(item.id));
    root.append(button);
  });
}

function renderAlertEvidence(items) {
  const root = $("alert-evidence");
  root.replaceChildren();
  $("alert-evidence-count").textContent = String(items?.length || 0);
  if (!items?.length) {
    const empty = document.createElement("p");
    empty.className = "mini-empty";
    empty.textContent = t("empty.noData");
    root.append(empty);
    return;
  }
  items.forEach((item) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "alert-evidence-item";
    button.textContent = String(item.type || "event") + " · " + String(item.id || "—");
    if (item.type === "event") {
      button.addEventListener("click", () => {
        if (openEventInInvestigate) openEventInInvestigate(item.id);
      });
    } else {
      button.disabled = true;
    }
    root.append(button);
  });
}

function renderAlertIocs(items) {
  const root = $("alert-iocs");
  if (!root) return;
  root.replaceChildren();
  if (!items?.length) {
    const empty = document.createElement("p");
    empty.className = "mini-empty";
    empty.textContent = t("alerts.noIocs");
    root.append(empty);
    return;
  }
  items.forEach((item) => {
    const card = document.createElement("div");
    card.className = "alert-evidence-item";
    const label = document.createElement("strong");
    label.textContent = String(item.type || "ioc") + " · " + String(item.value || "—");
    const meta = document.createElement("span");
    meta.className = "alert-list-meta";
    meta.textContent = t("alerts.iocEvidence") + ": " + String(item.evidence_event_id || "—");
    card.append(label, meta);
    root.append(card);
  });
}

function renderAlertNotes(items) {
  const root = $("alert-notes");
  root.replaceChildren();
  if (!items?.length) {
    const empty = document.createElement("p");
    empty.className = "mini-empty";
    empty.textContent = t("empty.noData");
    root.append(empty);
    return;
  }
  items.forEach((item) => {
    const card = document.createElement("article");
    card.className = "case-note";
    const time = document.createElement("time");
    time.textContent = formatDate(item.created_at);
    const body = document.createElement("p");
    body.textContent = item.body;
    card.append(time, body);
    root.append(card);
  });
}

export function renderAlertDetail(item) {
  state.selectedAlert = item;
  $("alert-empty").hidden = true;
  $("alert-detail-content").hidden = false;
  $("alert-title").textContent = item.title || item.rule_id;
  $("alert-rule").textContent = item.rule_id + " · v" + item.rule_version + " · schema " + item.schema_version;
  $("alert-severity").textContent = String(item.severity || "info").toUpperCase();
  $("alert-severity").className = "badge alert-severity " + String(item.severity || "info").toLowerCase();
  $("alert-confidence").textContent = String(item.confidence) + "%";
  $("alert-occurrences").textContent = String(item.occurrence_count || 1);
  $("alert-source").textContent = item.source_ip || "—";
  $("alert-session").textContent = item.session_id || "—";
  $("alert-description").textContent = item.description || "";
  $("alert-status").value = item.status || "new";
  $("alert-disposition").value = item.disposition || "";
  $("alert-tags").value = (item.tags || []).join(", ");
  renderAlertEvidence(item.evidence || []);
  renderAlertIocs(item.related_iocs || []);
  renderAlertNotes(item.notes || []);
  renderAlertList();
}

async function selectAlert(alertId) {
  const item = await safeGet("/api/v1/alerts/" + encodeURIComponent(alertId));
  if (item) renderAlertDetail(item);
}

export async function loadAlerts() {
  const params = new URLSearchParams();
  const status = $("alert-status-filter")?.value || "";
  const severity = $("alert-severity-filter")?.value || "";
  if (status) params.set("status", status);
  if (severity) params.set("severity", severity);
  params.set("limit", "200");
  const data = await safeGet("/api/v1/alerts?" + params.toString());
  if (!data) return;
  state.alerts = data.items || [];
  renderAlertList();
}

export async function saveAlert() {
  if (!state.selectedAlert?.id) return;
  try {
    const item = await requestJSON(
      "/api/v1/alerts/" + encodeURIComponent(state.selectedAlert.id),
      "PATCH",
      {
        status: $("alert-status").value,
        disposition: $("alert-disposition").value || null,
        tags: $("alert-tags").value.split(",").map((item) => item.trim()).filter(Boolean),
      }
    );
    renderAlertDetail(item);
    await loadAlerts();
  } catch (error) {
    console.error("AEGIS alert update failed", error);
  }
}

export async function addAlertNote(event) {
  event.preventDefault();
  if (!state.selectedAlert?.id) return;
  const body = $("alert-note").value.trim();
  if (!body) return;
  try {
    const item = await requestJSON(
      "/api/v1/alerts/" + encodeURIComponent(state.selectedAlert.id) + "/notes",
      "POST",
      {body}
    );
    $("alert-note").value = "";
    renderAlertDetail(item);
  } catch (error) {
    console.error("AEGIS alert note failed", error);
  }
}

export function seedCaseFromAlert() {
  if (!state.selectedAlert) return;
  const seen = new Set();
  const seed = [];
  const add = (type, id) => {
    if (!id) return;
    const key = type + ":" + id;
    if (seen.has(key)) return;
    seen.add(key);
    seed.push({type, id});
  };
  add("alert", state.selectedAlert.id);
  (state.selectedAlert.evidence || []).forEach((item) => {
    if (item.type === "event") add("event", item.id);
  });
  (state.selectedAlert.related_session_ids || []).forEach((id) => add("session", id));
  if (!caseSeeder) return;
  caseSeeder({
    seed,
    title: t("alerts.caseTitle")
      .replace("{rule}", state.selectedAlert.rule_id || t("common.unknown"))
      .replace("{ip}", state.selectedAlert.source_ip || t("common.unknown")),
    severity: state.selectedAlert.severity || "medium",
    tags: "alert, " + String(state.selectedAlert.rule_id || "detection"),
  });
}
