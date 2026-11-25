"use strict";

// Geospatial attack map view (Cycle L) as its own ES module (Cycle I, ADR 0003).
// Imports only from the leaf module core.js, so it carries no import cycle.
// The one orchestration dependency (re-running the global refresh when a map
// point sets the country filter) is inverted via an injected hook that app.js
// registers at bootstrap.
import { state, $, t, safeGet, currentParams, updateFilterCount } from "./core.js";

let onFilterRefresh = null;
export function setMapRefresh(fn) {
  onFilterRefresh = fn;
}

export function applyMapBox() {
  $("attack-map").setAttribute("viewBox", state.mapBox.join(" "));
}

export function zoomMap(factor) {
  const [x, y, width, height] = state.mapBox;
  const nextWidth = Math.min(800, Math.max(220, width * factor));
  const nextHeight = Math.min(390, Math.max(110, height * factor));
  state.mapBox = [
    Math.max(0, Math.min(800 - nextWidth, x + (width - nextWidth) / 2)),
    Math.max(0, Math.min(390 - nextHeight, y + (height - nextHeight) / 2)),
    nextWidth,
    nextHeight,
  ];
  applyMapBox();
}

export function renderGeoMap(geo) {
  const root = $("map-points");
  root.replaceChildren();
  const points = (geo && geo.points) || [];
  $("map-count").textContent = String(points.length);
  const unmapped = (geo && geo.unmapped) || {};
  $("map-unmapped").textContent = t("map.unmapped") + ": " + String(unmapped.events || 0);

  const maxCount = points.reduce((m, p) => Math.max(m, Number(p.count) || 0), 1);
  points.forEach((point) => {
    const lon = Number(point.lon), lat = Number(point.lat);
    if (!Number.isFinite(lon) || !Number.isFinite(lat)) return;
    const count = Math.max(1, Number(point.count) || 1);
    const severity = Math.max(0, Math.min(4, Number(point.severity_level) || 0));
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", String(((lon + 180) / 360) * 800));
    circle.setAttribute("cy", String(((90 - lat) / 180) * 390));
    circle.setAttribute("r", String(Math.min(12, 3 + Math.sqrt(count) * (0.8 + count / maxCount))));
    circle.setAttribute("class", "map-point sev-" + severity);
    circle.setAttribute("tabindex", "0");
    const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
    // textContent escapes attacker-controlled fields (country/asn).
    title.textContent = [
      t("map.location") + ": " + lat.toFixed(2) + ", " + lon.toFixed(2),
      (point.country || "—"),
      (point.asn || "—"),
      t("common.count") + ": " + count,
      t("map.ips") + ": " + (point.unique_source_ips || "—"),
      t("map.sessions") + ": " + (point.session_count || "—"),
      t("map.accuracy") + ": " + (point.accuracy_radius_km == null ? "—" : point.accuracy_radius_km + " km"),
    ].join(" · ");
    circle.append(title);
    const activate = () => {
      if (!point.country) return;
      state.filters.country = point.country;
      const select = $("filter-country");
      if (select) select.value = point.country;
      updateFilterCount();
      if (onFilterRefresh) onFilterRefresh();
    };
    circle.addEventListener("click", activate);
    circle.addEventListener("keydown", (event) => {
      if (event.key === "Enter") activate();
    });
    root.append(circle);
  });

  // Screen-reader / keyboard data-table equivalent of the top origins.
  const body = $("map-table-body");
  body.replaceChildren();
  points.slice(0, 50).forEach((point) => {
    const tr = document.createElement("tr");
    [point.country || "—", String(point.count ?? "—"),
     String(point.session_count ?? "—"),
     point.accuracy_radius_km == null ? "—" : point.accuracy_radius_km + " km"].forEach((value) => {
      const td = document.createElement("td");
      td.textContent = value;
      tr.append(td);
    });
    body.append(tr);
  });
}

export async function loadGeoMap(params) {
  const query = params ? params.toString() : currentParams().toString();
  const geo = await safeGet("/api/v1/geo/attacks?" + query);
  renderGeoMap(geo || {points: [], unmapped: {}});
}

export function toggleMapLive() {
  state.mapLive = !state.mapLive;
  const button = $("map-live");
  button.setAttribute("aria-pressed", state.mapLive ? "true" : "false");
  button.textContent = state.mapLive ? "⏸" : "▶";
  button.title = state.mapLive ? t("map.pause") : t("map.live");
  if (state.mapLiveTimer) { window.clearInterval(state.mapLiveTimer); state.mapLiveTimer = null; }
  if (state.mapLive) {
    state.mapLiveTimer = window.setInterval(() => { loadGeoMap(); }, 15000);
  }
}
