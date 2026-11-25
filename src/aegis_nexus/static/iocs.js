"use strict";

// IOC workspace view as its own ES module (Cycle I, ADR 0003).
// Imports only from the leaf module core.js. Its one cross-view dependency —
// opening a referenced event in the investigate view — is inverted via an
// injected opener hook that app.js registers at bootstrap, so there is no
// import cycle.
import { $, t, state, safeGet, formatDate, pretty } from "./core.js";

let openEventInInvestigate = null;
export function setIocEventOpener(fn) {
  openEventInInvestigate = fn;
}

function renderIocList() {
  const root = $("ioc-list");
  if (!root) return;
  root.replaceChildren();
  $("ioc-count").textContent = String(state.iocs.length);
  if (!state.iocs.length) {
    const empty = document.createElement("p");
    empty.className = "mini-empty";
    empty.textContent = t("iocs.empty");
    root.append(empty);
    return;
  }
  state.iocs.forEach((item) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "alert-list-item" + (state.selectedIoc?.id === item.id ? " selected" : "");
    const head = document.createElement("div");
    head.className = "alert-list-head";
    const value = document.createElement("strong");
    value.textContent = item.value;
    const kind = document.createElement("span");
    kind.className = "badge";
    kind.textContent = item.type;
    head.append(value, kind);
    const meta = document.createElement("span");
    meta.className = "alert-list-meta";
    meta.textContent = t("iocs.occurrences") + ": " + String(item.occurrences || 0)
      + " · " + t("iocs.sources") + ": " + String((item.source_ips || []).length);
    const time = document.createElement("span");
    time.className = "alert-list-meta";
    time.textContent = formatDate(item.last_seen);
    button.append(head, meta, time);
    button.addEventListener("click", () => selectIoc(item.id));
    root.append(button);
  });
}

function renderIocEvents(items) {
  const root = $("ioc-events");
  root.replaceChildren();
  $("ioc-event-count").textContent = String(items?.length || 0);
  (items || []).forEach((eventId) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "alert-evidence-item";
    button.textContent = "event · " + eventId;
    button.addEventListener("click", () => {
      if (openEventInInvestigate) openEventInInvestigate(eventId);
    });
    root.append(button);
  });
}

export function renderIocDetail(item) {
  state.selectedIoc = item;
  $("ioc-empty").hidden = true;
  $("ioc-detail-content").hidden = false;
  $("ioc-value").textContent = item.value || "—";
  $("ioc-id").textContent = item.id || "—";
  $("ioc-type").textContent = item.type || "—";
  $("ioc-first-seen").textContent = formatDate(item.first_seen);
  $("ioc-last-seen").textContent = formatDate(item.last_seen);
  $("ioc-occurrences").textContent = String(item.occurrences || 0);
  $("ioc-source-count").textContent = String((item.source_ips || []).length);
  $("ioc-pivots").textContent = pretty({
    source_ips: item.source_ips || [],
    session_ids: item.session_ids || [],
    honeypots: item.honeypots || [],
    services: item.services || [],
    alert_ids: item.alert_ids || [],
    case_ids: item.case_ids || [],
  });
  renderIocEvents(item.event_ids || []);
  renderIocList();
}

async function selectIoc(itemId) {
  const item = await safeGet(
    "/api/v1/iocs/" + encodeURIComponent(itemId) + "?hours=" + encodeURIComponent($("window").value)
  );
  if (item) renderIocDetail(item);
}

export async function loadIocs() {
  const params = new URLSearchParams();
  params.set("hours", $("window").value);
  params.set("limit", "300");
  const q = $("ioc-search")?.value.trim() || "";
  const type = $("ioc-type-filter")?.value || "";
  if (q) params.set("q", q);
  if (type) params.set("type", type);
  const data = await safeGet("/api/v1/iocs?" + params.toString());
  if (!data) return;
  state.iocs = data.items || [];
  renderIocList();
}
