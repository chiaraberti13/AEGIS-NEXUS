"use strict";

// Shared frontend core for the AEGIS-NEXUS console (ADR 0003, Cycle I).
//
// First ES-module extracted from the app.js IIFE: the central mutable `state`
// and the shared helpers (`$`, `t`, `pretty`, `apiHeaders`) that every view
// uses. This is a leaf module — it imports nothing from app.js — so it carries
// no import cycle; app.js imports from it as live bindings (the exported
// `state` object is shared and mutated in place).
//
// Per-view modules (dashboard/alerts/cases/map/…) are NOT split out yet: they
// call back into app.js helpers (refresh/updateFilterCount/safeGet), so
// extracting them today would introduce import cycles rather than cleaner
// boundaries (see ADR 0003). They stay in app.js until that can be resolved.

export const state = {
  lang: localStorage.getItem("aegis-lang") || "it",
  selected: null,
  session: null,
  ipProfile: null,
  behavioralAnalytics: null,
  dashboard: null,
  enrichmentStatus: null,
  operationsStatus: null,
  events: [],
  eventsCursor: null,
  eventsHasMore: false,
  eventsLoadingOlder: false,
  cases: [],
  selectedCase: null,
  alerts: [],
  selectedAlert: null,
  iocs: [],
  selectedIoc: null,
  mapLive: false,
  mapLiveTimer: null,
  auditItems: [],
  auditRetention: null,
  relationGraph: null,
  relationPathNodes: [],
  relationPathEdges: [],
  caseSeed: [],
  filters: {},
  mapBox: [0, 0, 800, 390],
  operatorKey: sessionStorage.getItem("aegis-operator-key") || "",
};

export const $ = (id) => document.getElementById(id);
export const t = (key) => (window.AEGIS_I18N[state.lang] || {})[key] || key;
export const pretty = (value) => JSON.stringify(value ?? {}, null, 2);

export function apiHeaders(extra = {}) {
  const headers = {Accept: "application/json", ...extra};
  if (state.operatorKey) headers["X-Aegis-Operator-Key"] = state.operatorKey;
  return headers;
}

// Injected by app.js at bootstrap so the network layer can live here (leaf)
// while the operator-gate UI stays in app.js — no import cycle.
let unauthorizedHandler = null;
export function setUnauthorizedHandler(fn) {
  unauthorizedHandler = fn;
}

export async function getJSON(url) {
  const response = await fetch(url, {headers: apiHeaders()});
  if (response.status === 401 && url !== "/api/v1/operator/status" && unauthorizedHandler) {
    unauthorizedHandler();
  }
  if (!response.ok) throw new Error("HTTP " + response.status);
  return response.json();
}

export async function safeGet(url) {
  try {
    return await getJSON(url);
  } catch (error) {
    console.error("AEGIS request failed", error);
    return null;
  }
}

export function currentParams() {
  const params = new URLSearchParams();
  const q = $("global-search").value.trim();
  if (q) params.set("q", q);
  params.set("hours", $("window").value);
  Object.entries(state.filters).forEach(([key, value]) => {
    if (value) params.set(key, value);
  });
  return params;
}

export function feedParams() {
  const params = currentParams();
  params.set("limit", "120");
  return params;
}

export function activeFilterCount() {
  return Object.values(state.filters).filter(Boolean).length;
}

export function updateFilterCount() {
  $("active-filter-count").textContent = String(activeFilterCount());
}
