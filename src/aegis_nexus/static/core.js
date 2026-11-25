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
