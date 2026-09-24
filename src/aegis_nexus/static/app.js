"use strict";

(() => {
  const state = {
    lang: localStorage.getItem("aegis-lang") || "it",
    selected: null,
    session: null,
    ipProfile: null,
    eventStudy: null,
    sessionStudy: null,
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
    relationGraph: null,
    relationPathNodes: [],
    relationPathEdges: [],
    caseSeed: [],
    filters: {},
    mapBox: [0, 0, 800, 390],
    operatorKey: sessionStorage.getItem("aegis-operator-key") || "",
  };

  const $ = (id) => document.getElementById(id);
  const t = (key) => (window.AEGIS_I18N[state.lang] || {})[key] || key;
  const pretty = (value) => JSON.stringify(value ?? {}, null, 2);

  function apiHeaders(extra = {}) {
    const headers = {Accept: "application/json", ...extra};
    if (state.operatorKey) headers["X-Aegis-Operator-Key"] = state.operatorKey;
    return headers;
  }

  function showOperatorGate(invalid = false) {
    $("operator-gate").hidden = false;
    $("operator-error").hidden = !invalid;
    window.setTimeout(() => $("operator-key").focus(), 0);
  }

  function hideOperatorGate() {
    $("operator-gate").hidden = true;
    $("operator-error").hidden = true;
    $("operator-key").value = "";
  }

  async function getJSON(url) {
    const response = await fetch(url, {headers: apiHeaders()});
    if (response.status === 401 && url !== "/api/v1/operator/status") showOperatorGate(true);
    if (!response.ok) throw new Error("HTTP " + response.status);
    return response.json();
  }

  async function requestJSON(url, method, payload) {
    const response = await fetch(url, {
      method,
      headers: apiHeaders({"Content-Type": "application/json"}),
      body: payload === undefined ? undefined : JSON.stringify(payload),
    });
    if (response.status === 401) showOperatorGate(true);
    if (!response.ok) {
      let detail = "";
      try {
        const body = await response.json();
        detail = body.detail || body.error || "";
      } catch {}
      throw new Error("HTTP " + response.status + (detail ? " · " + detail : ""));
    }
    if (response.status === 204) return null;
    return response.json();
  }

  async function safeGet(url) {
    try {
      return await getJSON(url);
    } catch (error) {
      console.error("AEGIS request failed", error);
      return null;
    }
  }

  function i18n() {
    document.documentElement.lang = state.lang;
    document.querySelectorAll("[data-i18n]").forEach((node) => {
      node.textContent = t(node.dataset.i18n);
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
      node.placeholder = t(node.dataset.i18nPlaceholder);
    });
    document.querySelectorAll("[data-i18n-title]").forEach((node) => {
      node.title = t(node.dataset.i18nTitle);
    });
    document.querySelectorAll("[data-i18n-aria]").forEach((node) => {
      node.setAttribute("aria-label", t(node.dataset.i18nAria));
    });
    $("lang-toggle").textContent = state.lang === "it" ? "EN" : "IT";
    refreshFilterLabels();
    if (state.dashboard?.analysis?.truncated) {
      $("analytics-warning").textContent = t("analytics.truncated").replace("{limit}", String(state.dashboard.analysis.event_limit));
    }
    renderEnrichmentStatus();
    renderOperationsStatus();
    renderEventPagination();
    if (state.relationGraph) {
      populateGraphKindFilter(state.relationGraph.nodes || []);
      renderRelations(state.relationGraph);
    }
  }

  function renderOperationsStatus() {
    const label = $("collector-status");
    const dot = $("collector-status-dot");
    const telemetryNode = $("sensor-telemetry-status");
    if (!label || !dot || !telemetryNode) return;

    const status = state.operationsStatus;
    dot.classList.remove("degraded", "unknown");
    if (!status) {
      label.textContent = t("status.collectorUnknown");
      dot.classList.add("unknown");
      telemetryNode.textContent = "";
      return;
    }

    const ready = status.collector?.ready === true;
    label.textContent = t(ready ? "status.collectorReady" : "status.collectorDegraded");
    if (!ready) dot.classList.add("degraded");

    const telemetry = status.telemetry || {};
    const hours = String(telemetry.recent_hours || 24);
    if ((telemetry.configured_sensors || 0) > 0) {
      telemetryNode.textContent = t("status.telemetryConfigured")
        .replace("{hours}", hours)
        .replace("{recent}", String(telemetry.configured_with_recent_telemetry || 0))
        .replace("{configured}", String(telemetry.configured_sensors || 0));
    } else {
      telemetryNode.textContent = t("status.telemetryObserved")
        .replace("{hours}", hours)
        .replace("{observed}", String(telemetry.observed_sensor_ids || 0));
    }
    telemetryNode.title = t("status.telemetryHint");
  }

  async function loadOperationsStatus() {
    const data = await safeGet("/api/v1/operations/status?hours=24");
    state.operationsStatus = data;
    renderOperationsStatus();
  }

  function renderEnrichmentStatus() {
    const node = $("enrichment-status");
    if (!node) return;
    const status = state.enrichmentStatus;
    let key = "status.enrichmentDisabled";
    let level = "disabled";
    if (status?.configured) {
      const configured = [status.city, status.asn].filter((item) => item?.configured);
      const ready = configured.filter((item) => item?.ready);
      if (configured.length && ready.length === configured.length) {
        key = "status.enrichmentReady";
        level = "ready";
      } else {
        key = "status.enrichmentPartial";
        level = "partial";
      }
    }
    node.className = "sidebar-substatus " + level;
    node.textContent = t(key);
  }

  async function loadEnrichmentStatus() {
    const data = await safeGet("/api/v1/enrichment/status");
    if (!data) return;
    state.enrichmentStatus = data;
    renderEnrichmentStatus();
  }

  function renderThreatContextStatus() {
    const node = $("threat-context-status");
    if (!node) return;
    const status = state.threatContextStatus;
    let key = "status.threatContextDisabled";
    let level = "disabled";
    if (status?.configured) {
      if (status.ready) {
        key = "status.threatContextReady";
        level = "ready";
      } else {
        key = "status.threatContextError";
        level = "partial";
      }
    }
    node.className = "sidebar-substatus " + level;
    node.textContent = t(key);
  }

  async function loadThreatContextStatus() {
    const data = await safeGet("/api/v1/threat-context/status");
    if (!data) return;
    state.threatContextStatus = data;
    renderThreatContextStatus();
  }

  function showView(name) {
    document.querySelectorAll("[data-view]").forEach((node) => {
      node.classList.toggle("active", node.dataset.view === name);
    });
    document.querySelectorAll("[data-view-target]").forEach((node) => {
      node.classList.toggle("active", node.dataset.viewTarget === name);
    });
  }

  function option(value, label) {
    const node = document.createElement("option");
    node.value = value;
    node.textContent = label;
    return node;
  }

  function populateFilter(key, values) {
    const id = key === "event_type" ? "filter-event-type" : "filter-" + key;
    const select = $(id);
    if (!select) return;
    const current = state.filters[key] || "";
    select.replaceChildren(option("", t("filters.all." + key)));
    (values || []).forEach((value) => select.append(option(value, value)));
    if ([...select.options].some((item) => item.value === current)) select.value = current;
  }

  function refreshFilterLabels() {
    ["country", "asn", "destination_port", "protocol", "service", "honeypot", "severity", "event_type"].forEach((key) => {
      const id = key === "event_type" ? "filter-event-type" : "filter-" + key;
      const select = $(id);
      if (select && select.options.length) select.options[0].textContent = t("filters.all." + key);
    });
  }

  async function loadFilterOptions() {
    const data = await safeGet("/api/v1/meta/filters?hours=" + encodeURIComponent($("window").value));
    if (!data) return;
    ["country", "asn", "destination_port", "protocol", "service", "honeypot", "severity", "event_type"].forEach((key) => {
      populateFilter(key, data[key]);
    });
  }

  function currentParams() {
    const params = new URLSearchParams();
    const q = $("global-search").value.trim();
    if (q) params.set("q", q);
    params.set("hours", $("window").value);
    Object.entries(state.filters).forEach(([key, value]) => {
      if (value) params.set(key, value);
    });
    return params;
  }

  function feedParams() {
    const params = currentParams();
    params.set("limit", "120");
    return params;
  }

  function activeFilterCount() {
    return Object.values(state.filters).filter(Boolean).length;
  }

  function updateFilterCount() {
    $("active-filter-count").textContent = String(activeFilterCount());
  }

  function setFilter(key, value) {
    state.filters[key] = value || "";
    const id = key === "event_type" ? "filter-event-type" : "filter-" + key;
    if ($(id)) $(id).value = state.filters[key];
    updateFilterCount();
    refresh();
  }

  function bars(id, items, behavior = {}) {
    const root = $(id);
    root.replaceChildren();
    if (!items?.length) {
      const empty = document.createElement("div");
      empty.className = "mini-empty";
      empty.textContent = t("empty.noData");
      root.append(empty);
      return;
    }
    const max = Math.max(...items.map((item) => Number(item.value) || 0), 1);
    items.slice(0, 9).forEach((item) => {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "bar-row";
      const label = document.createElement("span");
      label.className = "bar-label";
      label.textContent = String(item.label);
      const track = document.createElement("span");
      track.className = "bar-track";
      const fill = document.createElement("span");
      fill.className = "bar-fill";
      fill.style.width = Math.max(2, (Number(item.value) / max) * 100) + "%";
      const value = document.createElement("strong");
      value.textContent = String(item.value);
      track.append(fill);
      row.append(label, track, value);
      if (behavior.filterKey) {
        row.addEventListener("click", () => setFilter(behavior.filterKey, String(item.label)));
      } else if (behavior.search) {
        row.addEventListener("click", () => {
          $("global-search").value = String(item.label);
          refresh();
        });
      } else {
        row.disabled = true;
      }
      root.append(row);
    });
  }

  function timeline(id, items) {
    const svg = $(id);
    svg.replaceChildren();
    if (!items?.length) return;
    const W = 900, H = 260, P = 28;
    const max = Math.max(...items.map((item) => Number(item.value) || 0), 1);
    const points = items.map((item, index) => [
      P + index * (W - P * 2) / Math.max(items.length - 1, 1),
      H - P - (Number(item.value) / max) * (H - P * 2),
    ]);
    const grid = document.createElementNS("http://www.w3.org/2000/svg", "g");
    grid.setAttribute("class", "timeline-grid");
    for (let i = 0; i < 5; i += 1) {
      const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      const y = P + i * ((H - P * 2) / 4);
      [["x1", P], ["x2", W - P], ["y1", y], ["y2", y]].forEach(([key, value]) => line.setAttribute(key, String(value)));
      grid.append(line);
    }
    const polyline = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
    polyline.setAttribute("points", points.map((point) => point.join(",")).join(" "));
    polyline.setAttribute("class", "timeline-line");
    svg.append(grid, polyline);
    points.forEach(([x, y], index) => {
      const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("cx", String(x));
      circle.setAttribute("cy", String(y));
      circle.setAttribute("r", "3");
      circle.setAttribute("class", "timeline-dot");
      const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
      title.textContent = items[index].label + ": " + items[index].value;
      circle.append(title);
      svg.append(circle);
    });
  }

  function applyMapBox() {
    $("attack-map").setAttribute("viewBox", state.mapBox.join(" "));
  }

  function zoomMap(factor) {
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

  function map(points) {
    const root = $("map-points");
    root.replaceChildren();
    $("map-count").textContent = String(points?.length || 0);
    const grouped = new Map();
    (points || []).forEach((point) => {
      const lon = Number(point.lon), lat = Number(point.lat);
      if (!Number.isFinite(lon) || !Number.isFinite(lat)) return;
      const key = lat.toFixed(1) + "|" + lon.toFixed(1) + "|" + (point.source_ip || "");
      const existing = grouped.get(key) || {...point, count: 0, lon, lat};
      existing.count += Math.max(1, Number(point.count) || 1);
      if (!existing.session_count && point.session_count) existing.session_count = point.session_count;
      grouped.set(key, existing);
    });
    grouped.forEach((point) => {
      const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("cx", String(((point.lon + 180) / 360) * 800));
      circle.setAttribute("cy", String(((90 - point.lat) / 180) * 390));
      circle.setAttribute("r", String(Math.min(10, 3.5 + Math.sqrt(point.count))));
      circle.setAttribute("class", "map-point");
      circle.setAttribute("tabindex", "0");
      const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
      const mapDetails = [
        t("map.point") + ": " + (point.source_ip || "—"),
        point.country || "—",
        (point.asn || "—"),
        t("common.count") + ": " + point.count,
        t("map.sessions") + ": " + (point.session_count || "—"),
        t("map.services") + ": " + ((point.services || []).join(", ") || "—"),
        t("map.ports") + ": " + ((point.destination_ports || []).join(", ") || "—"),
      ];
      title.textContent = mapDetails.join(" · ");
      circle.append(title);
      const activate = () => {
        if (!point.source_ip) return;
        $("global-search").value = point.source_ip;
        showView("investigate");
        refresh();
      };
      circle.addEventListener("click", activate);
      circle.addEventListener("keydown", (event) => {
        if (event.key === "Enter") activate();
      });
      root.append(circle);
    });
  }

  function heat(matrix) {
    const root = $("heatmap");
    root.replaceChildren();
    const values = (matrix || []).flat();
    const max = Math.max(...values, 1);
    (matrix || []).forEach((row, day) => row.forEach((value, hour) => {
      const cell = document.createElement("div");
      cell.className = "heat-cell";
      cell.style.opacity = String(.14 + .86 * (Number(value) / max));
      cell.title = String(day + 1) + " · " + hour + ":00 · " + value;
      root.append(cell);
    }));
  }

  function severityBadge(value) {
    const node = document.createElement("span");
    node.className = "severity " + (value || "info");
    node.textContent = value || "info";
    return node;
  }

  function formatTime(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit"});
  }

  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleString();
  }

  function renderEventPagination() {
    const button = $("event-load-older");
    if (!button) return;
    button.hidden = !state.eventsHasMore && !state.eventsLoadingOlder;
    button.disabled = state.eventsLoadingOlder;
    button.textContent = t(state.eventsLoadingOlder ? "feed.loadingOlder" : "feed.loadOlder");
  }

  async function loadOlderEvents() {
    if (state.eventsLoadingOlder || !state.eventsHasMore || !state.eventsCursor) return;
    const requestCursor = state.eventsCursor;
    state.eventsLoadingOlder = true;
    renderEventPagination();
    const params = feedParams();
    params.set("cursor", requestCursor);
    try {
      const page = await getJSON("/api/v1/events?" + params.toString());
      if (state.eventsCursor !== requestCursor) return;
      const known = new Set(state.events.map((item) => item.id));
      (page.items || []).forEach((item) => {
        if (!known.has(item.id)) {
          known.add(item.id);
          state.events.push(item);
        }
      });
      state.eventsCursor = page.next_cursor || null;
      state.eventsHasMore = page.has_more === true;
      renderFeed("event-feed", state.events, state.events.length || 120);
    } catch (error) {
      console.error("AEGIS historical feed pagination failed", error);
      await refresh();
    } finally {
      state.eventsLoadingOlder = false;
      renderEventPagination();
    }
  }

  function renderFeed(rootId, events, limit = 120) {
    const body = $(rootId);
    body.replaceChildren();
    const selected = (events || []).slice(0, limit);
    if (!selected.length) {
      const row = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = 5;
      cell.className = "mini-empty";
      cell.textContent = t("empty.noData");
      row.append(cell);
      body.append(row);
      return;
    }
    selected.forEach((event) => {
      const row = document.createElement("tr");
      row.tabIndex = 0;
      if (state.selected?.id === event.id) row.classList.add("selected");
      const cells = [
        formatTime(event.timestamp),
        event.source_ip || "—",
        event.event_type,
        event.service || event.observed?.service || "—",
      ];
      cells.forEach((value) => {
        const cell = document.createElement("td");
        cell.textContent = String(value);
        row.append(cell);
      });
      const severityCell = document.createElement("td");
      severityCell.append(severityBadge(event.severity));
      row.append(severityCell);
      const activate = () => selectEvent(event, true);
      row.addEventListener("click", activate);
      row.addEventListener("keydown", (keyboardEvent) => {
        if (keyboardEvent.key === "Enter") activate();
      });
      body.append(row);
    });
  }

  function fact(root, label, value) {
    const item = document.createElement("div");
    item.className = "fact";
    const key = document.createElement("span");
    key.textContent = label;
    const val = document.createElement("strong");
    val.textContent = Array.isArray(value) ? (value.join(", ") || "—") : String(value ?? "—");
    item.append(key, val);
    root.append(item);
  }

  function rankedLabels(items) {
    return (items || []).map((item) => String(item.label) + " (" + String(item.value) + ")");
  }

  function renderIp(profile) {
    const root = $("ip-profile");
    root.replaceChildren();
    if (!profile) {
      fact(root, t("empty.noData"), "—");
      return;
    }
    fact(root, t("ip.events"), profile.event_count);
    fact(root, t("ip.sessions"), profile.sessions?.length || 0);
    fact(root, t("ip.firstSeen"), formatDate(profile.first_seen));
    fact(root, t("ip.lastSeen"), formatDate(profile.last_seen));
    fact(root, t("ip.services"), profile.services || []);
    fact(root, t("ip.ports"), profile.destination_ports || []);
    fact(root, t("ip.asn"), profile.asns || []);
    fact(root, t("ip.country"), profile.countries || []);
    const activity = profile.activity || {};
    fact(root, t("ip.eventTypes"), rankedLabels(activity.event_types));
    fact(root, t("ip.honeypots"), rankedLabels(activity.honeypots));
    fact(root, t("ip.usernames"), rankedLabels(activity.usernames));
    fact(root, t("ip.passwordFingerprints"), rankedLabels(activity.credential_secret_fingerprints));
    fact(root, t("ip.commands"), rankedLabels(activity.commands));
    fact(root, t("ip.payloads"), rankedLabels(activity.payloads));
    fact(root, t("ip.ids"), rankedLabels(activity.ids_alerts));
    fact(root, t("ip.mitre"), rankedLabels(activity.mitre));
    fact(root, t("ip.cve"), rankedLabels(activity.cves));
    fact(root, t("ip.ioc"), rankedLabels(activity.iocs));
  }

  function renderSession(bundle) {
    const root = $("session-summary");
    root.replaceChildren();
    if (!bundle) {
      fact(root, t("empty.noSession"), "—");
      return;
    }
    const summary = bundle.summary || {};
    const correlation = summary.correlation || {};
    fact(root, t("session.correlation"), t("session.correlation." + (summary.correlation_method || "temporal_fallback")));
    fact(root, t("session.correlationStrength"), t("session.correlationStrength." + (correlation.strength || "heuristic")));
    if (Array.isArray(correlation.basis) && correlation.basis.length) {
      fact(root, t("session.correlationBasis"), correlation.basis);
    }
    fact(root, t("session.events"), summary.event_count || 0);
    fact(root, t("session.credentials"), summary.credentials || 0);
    fact(root, t("session.commands"), summary.commands || 0);
    fact(root, t("session.payloads"), summary.payloads || 0);
    fact(root, t("session.ids"), summary.ids_alerts || 0);
    fact(root, t("session.mitre"), summary.mitre || []);
    fact(root, t("session.ioc"), summary.iocs || 0);
    if (summary.truncated) {
      fact(
        root,
        t("session.analysisScope"),
        t("session.latestEventsOnly").replace("{limit}", String(bundle.analysis?.event_limit || summary.events_returned || "—")),
      );
    }
  }

  function renderThreatIntelligence(data) {
    const root = $("ti-list");
    root.replaceChildren();
    const items = data?.items || [];
    if (!items.length) {
      const empty = document.createElement("p");
      empty.className = "mini-empty";
      empty.textContent = t("empty.noTI");
      root.append(empty);
      return;
    }
    items.forEach((item) => {
      const card = document.createElement("article");
      card.className = "ti-item";
      const head = document.createElement("div");
      head.className = "ti-head";
      const kind = document.createElement("strong");
      kind.textContent = item.kind || "enrichment";
      const badge = document.createElement("span");
      badge.className = "provenance enrichment";
      badge.textContent = item.classification === "threat_intelligence"
        ? t("ti.threatIntelligence")
        : t("ti.contextEnrichment");
      head.append(kind, badge);
      const meta = document.createElement("p");
      meta.className = "muted";
      meta.textContent = t("common.source") + ": " + (item.source || "—") + " · " + t("common.observedAt") + ": " + formatDate(item.observed_at);
      const pre = document.createElement("pre");
      pre.textContent = pretty(item.data);
      card.append(head, meta, pre);
      root.append(card);
    });
  }

  function eventArtifact(event) {
    const observed = event.observed || {};
    const credential = observed.credential;
    if (credential && typeof credential === "object" && credential.username) return "user=" + credential.username;
    if (observed.command) return String(observed.command).slice(0, 120);
    if (observed.payload) return String(observed.payload).slice(0, 120);
    const alert = observed.alert;
    if (alert && typeof alert === "object" && alert.signature) return String(alert.signature).slice(0, 120);
    return "";
  }

  function renderSessionTimeline(bundle) {
    const root = $("session-timeline");
    root.replaceChildren();
    const events = bundle?.events || [];
    if (!events.length) {
      const empty = document.createElement("p");
      empty.className = "mini-empty";
      empty.textContent = t("empty.noData");
      root.append(empty);
      return;
    }
    events.forEach((event) => {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "session-event";
      const marker = document.createElement("span");
      marker.className = "timeline-marker " + (event.severity || "info");
      const body = document.createElement("span");
      body.className = "session-event-body";
      const top = document.createElement("span");
      top.className = "session-event-top";
      const time = document.createElement("time");
      time.textContent = formatTime(event.timestamp);
      const type = document.createElement("strong");
      type.textContent = event.event_type;
      top.append(time, type);
      const artifact = document.createElement("span");
      artifact.className = "muted";
      artifact.textContent = eventArtifact(event) || (event.service || "—") + " · " + (event.destination_port || "—");
      body.append(top, artifact);
      row.append(marker, body);
      row.addEventListener("click", () => selectEvent(event, false));
      root.append(row);
    });
  }

  function renderStudySection(root, title, values) {
    if (!values?.length) return;
    const section = document.createElement("section");
    const heading = document.createElement("h3");
    heading.textContent = title;
    const list = document.createElement("ul");
    values.forEach((value) => {
      const item = document.createElement("li");
      item.textContent = String(value);
      list.append(item);
    });
    section.append(heading, list);
    root.append(section);
  }

  function renderEventStudy(data) {
    const root = $("event-study");
    root.replaceChildren();
    if (!data) {
      const empty = document.createElement("p");
      empty.className = "empty";
      empty.textContent = t("study.selectEvent");
      root.append(empty);
      return;
    }
    const heading = document.createElement("h3");
    heading.textContent = data.title || "";
    const whyTitle = document.createElement("span");
    whyTitle.className = "provenance study";
    whyTitle.textContent = t("study.why");
    const why = document.createElement("p");
    why.textContent = data.why_interesting || "";
    root.append(heading, whyTitle, why);
    renderStudySection(root, t("study.checklist"), data.soc_checklist);
    renderStudySection(root, t("study.questions"), data.questions);
    renderStudySection(root, t("study.limitations"), data.limitations);
  }

  function renderSessionStudy(data) {
    const root = $("session-study");
    root.replaceChildren();
    if (!data) {
      const empty = document.createElement("p");
      empty.className = "empty";
      empty.textContent = t("study.selectEvent");
      root.append(empty);
      return;
    }
    const heading = document.createElement("h3");
    heading.textContent = data.title || "";
    root.append(heading);
    renderStudySection(root, t("study.facts"), data.facts);
    renderStudySection(root, t("study.focus"), data.focus);
    renderStudySection(root, t("study.next"), data.next_steps);
    renderStudySection(root, t("study.limitations"), data.limitations);
  }

  function graphKindLabel(kind) {
    const key = "relations.kind." + String(kind || "unknown");
    const label = t(key);
    return label === key ? String(kind || t("common.unknown")) : label;
  }

  function graphRelationLabel(relation) {
    const key = "relations.edge." + String(relation || "unknown");
    const label = t(key);
    return label === key ? String(relation || t("common.unknown")) : label;
  }

  function graphPosition(nodes) {
    const positions = new Map();
    const session = nodes.find((node) => node.kind === "session");
    if (session) positions.set(session.id, {x: 500, y: 310});
    const events = nodes.filter((node) => node.kind === "event");
    const others = nodes.filter((node) => node.kind !== "event" && (!session || node.id !== session.id));
    events.forEach((node, index) => {
      const angle = (Math.PI * 2 * index / Math.max(events.length, 1)) - Math.PI / 2;
      positions.set(node.id, {x: 500 + Math.cos(angle) * 150, y: 310 + Math.sin(angle) * 150});
    });
    others.forEach((node, index) => {
      const angle = (Math.PI * 2 * index / Math.max(others.length, 1)) - Math.PI / 2;
      positions.set(node.id, {x: 500 + Math.cos(angle) * 270, y: 310 + Math.sin(angle) * 250});
    });
    return positions;
  }

  function graphLegend(nodes) {
    const root = $("graph-legend");
    root.replaceChildren();
    const kinds = [...new Set((nodes || []).map((node) => node.kind))].sort();
    kinds.forEach((kind) => {
      const item = document.createElement("span");
      item.className = "legend-item";
      const dot = document.createElement("i");
      dot.className = "legend-dot kind-" + kind;
      const label = document.createElement("span");
      label.textContent = graphKindLabel(kind);
      item.append(dot, label);
      root.append(item);
    });
  }

  function graphEdgeKey(edge) {
    const endpoints = [String(edge.source), String(edge.target)].sort();
    return endpoints.join("|") + "|" + String(edge.relation || "");
  }

  function populateGraphPathSelectors(nodes) {
    const options = (nodes || []).map((node) => ({
      value: node.id,
      label: graphKindLabel(node.kind) + " · " + String(node.label).slice(0, 72),
    }));
    [["graph-path-from", "relations.pathFrom"], ["graph-path-to", "relations.pathTo"]].forEach(([id, placeholder]) => {
      const select = $(id);
      const previous = select.value;
      select.replaceChildren();
      const empty = document.createElement("option");
      empty.value = "";
      empty.textContent = t(placeholder);
      select.append(empty);
      options.forEach((item) => {
        const option = document.createElement("option");
        option.value = item.value;
        option.textContent = item.label;
        select.append(option);
      });
      if (options.some((item) => item.value === previous)) select.value = previous;
    });
  }

  function clearGraphPath() {
    state.relationPathNodes = [];
    state.relationPathEdges = [];
  }

  function findGraphPath() {
    if (!state.relationGraph) return;
    const scoped = graphScope(state.relationGraph);
    const source = $("graph-path-from").value;
    const target = $("graph-path-to").value;
    if (!source || !target) return;

    const warning = $("relation-warning");
    const adjacency = new Map(scoped.nodes.map((node) => [node.id, []]));
    scoped.edges.forEach((edge) => {
      const key = graphEdgeKey(edge);
      adjacency.get(edge.source)?.push({next: edge.target, key});
      adjacency.get(edge.target)?.push({next: edge.source, key});
    });

    const parent = new Map([[source, null]]);
    const queue = [source];
    while (queue.length && !parent.has(target)) {
      const current = queue.shift();
      (adjacency.get(current) || []).forEach((step) => {
        if (parent.has(step.next)) return;
        parent.set(step.next, {node: current, edge: step.key});
        queue.push(step.next);
      });
    }

    if (!parent.has(target)) {
      clearGraphPath();
      warning.hidden = false;
      warning.textContent = t("relations.noPath");
      return;
    }

    const nodes = [target];
    const edges = [];
    let current = target;
    while (current !== source) {
      const step = parent.get(current);
      if (!step) break;
      edges.push(step.edge);
      current = step.node;
      nodes.push(current);
    }
    state.relationPathNodes = nodes;
    state.relationPathEdges = edges;
    renderRelations(state.relationGraph);
  }

  function populateGraphKindFilter(nodes) {
    const select = $("graph-kind-filter");
    const previous = select.value;
    const kinds = [...new Set((nodes || []).map((node) => node.kind))].sort();
    select.replaceChildren();
    const all = document.createElement("option");
    all.value = "";
    all.textContent = t("relations.allKinds");
    select.append(all);
    kinds.forEach((kind) => {
      const option = document.createElement("option");
      option.value = kind;
      option.textContent = graphKindLabel(kind);
      select.append(option);
    });
    if (kinds.includes(previous)) select.value = previous;
  }

  function graphScope(graph) {
    let nodes = [...(graph?.nodes || [])];
    let edges = [...(graph?.edges || [])];

    if ($("graph-evidence-only")?.checked) {
      const allowed = new Set(nodes.filter((node) => node.provenance !== "enrichment").map((node) => node.id));
      nodes = nodes.filter((node) => allowed.has(node.id));
      edges = edges.filter((edge) => allowed.has(edge.source) && allowed.has(edge.target));
    }

    const depthValue = $("graph-depth")?.value || "all";
    if (depthValue !== "all") {
      const maxDepth = Number(depthValue);
      const root = nodes.find((node) => node.kind === "session");
      if (root && Number.isFinite(maxDepth)) {
        const adjacency = new Map(nodes.map((node) => [node.id, new Set()]));
        edges.forEach((edge) => {
          adjacency.get(edge.source)?.add(edge.target);
          adjacency.get(edge.target)?.add(edge.source);
        });
        const distance = new Map([[root.id, 0]]);
        const queue = [root.id];
        while (queue.length) {
          const current = queue.shift();
          const currentDepth = distance.get(current) || 0;
          if (currentDepth >= maxDepth) continue;
          (adjacency.get(current) || []).forEach((next) => {
            if (distance.has(next)) return;
            distance.set(next, currentDepth + 1);
            queue.push(next);
          });
        }
        const allowed = new Set([...distance.entries()].filter(([, value]) => value <= maxDepth).map(([id]) => id));
        nodes = nodes.filter((node) => allowed.has(node.id));
        edges = edges.filter((edge) => allowed.has(edge.source) && allowed.has(edge.target));
      }
    }

    const kind = $("graph-kind-filter")?.value || "";
    if (kind) {
      const allowed = new Set(
        nodes
          .filter((node) => node.kind === kind || node.kind === "event" || node.kind === "session")
          .map((node) => node.id)
      );
      nodes = nodes.filter((node) => allowed.has(node.id));
      edges = edges.filter((edge) => allowed.has(edge.source) && allowed.has(edge.target));
    }
    return {nodes, edges};
  }

  function renderRelations(graph) {
    const svg = $("relation-graph");
    svg.replaceChildren();
    const warning = $("relation-warning");
    warning.hidden = true;
    warning.textContent = "";

    const scoped = graphScope(graph);
    const nodes = scoped.nodes;
    const allowedIds = new Set(nodes.map((node) => node.id));
    const edges = scoped.edges.filter((edge) => allowedIds.has(edge.source) && allowedIds.has(edge.target));
    const graphAnalysis = graph?.analysis || {};
    if (graphAnalysis.graph_truncated) {
      warning.hidden = false;
      warning.textContent = t("relations.truncated")
        .replace("{limit}", String(graphAnalysis.graph_node_limit || nodes.length))
        .replace("{nodes}", String(graphAnalysis.graph_nodes_returned || nodes.length));
    }
    $("relation-count").textContent = String(nodes.length);
    graphLegend(nodes);
    populateGraphPathSelectors(nodes);
    if (!nodes.length) return;
    const positions = graphPosition(nodes);
    const highlightedNodes = new Set(state.relationPathNodes || []);
    const highlightedEdges = new Set(state.relationPathEdges || []);

    edges.forEach((edge) => {
      const source = positions.get(edge.source), target = positions.get(edge.target);
      if (!source || !target) return;
      const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      [["x1", source.x], ["y1", source.y], ["x2", target.x], ["y2", target.y]].forEach(([key, value]) => line.setAttribute(key, String(value)));
      const provenance = edge.provenance || "observed";
      const highlighted = highlightedEdges.has(graphEdgeKey(edge)) ? " path-highlight" : "";
      line.setAttribute("class", "relation-edge provenance-" + provenance + highlighted);
      const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
      title.textContent = graphRelationLabel(edge.relation) + " · " + t("provenance." + provenance);
      line.append(title);
      svg.append(line);
    });

    nodes.forEach((node) => {
      const position = positions.get(node.id);
      if (!position) return;
      const group = document.createElementNS("http://www.w3.org/2000/svg", "g");
      const highlighted = highlightedNodes.has(node.id) ? " path-highlight" : "";
      group.setAttribute("class", "relation-node kind-" + node.kind + " provenance-" + (node.provenance || "observed") + highlighted);
      group.setAttribute("tabindex", "0");
      const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("cx", String(position.x));
      circle.setAttribute("cy", String(position.y));
      circle.setAttribute("r", node.kind === "session" ? "16" : node.kind === "event" ? "10" : "12");
      const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
      label.setAttribute("x", String(position.x + 15));
      label.setAttribute("y", String(position.y + 4));
      label.textContent = String(node.label).slice(0, 22);
      const inspect = () => {
        $("graph-node-kind").textContent = graphKindLabel(node.kind);
        $("graph-node-label").textContent = node.label;
        const provenance = node.provenance || "observed";
        const provenanceNode = $("graph-node-provenance");
        provenanceNode.className = "provenance " + provenance;
        provenanceNode.textContent = t("provenance." + provenance);
        $("graph-node-metadata").textContent = node.metadata ? pretty(node.metadata) : "";
      };
      group.addEventListener("click", inspect);
      group.addEventListener("keydown", (event) => {
        if (event.key === "Enter") inspect();
      });
      group.append(circle, label);
      svg.append(group);
    });
  }

  async function expandGraphCorrelations() {
    const graph = state.relationGraph;
    if (!graph) return;
    const root = (graph.nodes || []).find((node) => node.kind === "session" && !node.metadata?.cross_session_correlation);
    if (!root) return;
    const params = new URLSearchParams({
      session_id: String(root.label),
      hours: String($("window").value),
      limit: "20",
      min_score: "0.5",
    });
    const data = await safeGet("/api/v1/correlations?" + params.toString());
    if (!data) return;

    const nodes = [...(graph.nodes || [])];
    const edges = [...(graph.edges || [])];
    const nodeIds = new Set(nodes.map((node) => node.id));
    const edgeIds = new Set(edges.map((edge) => [edge.source, edge.target, edge.relation].join("|")));
    (data.items || []).forEach((item) => {
      const nodeId = "related-session:" + String(item.session_id);
      if (!nodeIds.has(nodeId)) {
        nodes.push({
          id: nodeId,
          kind: "session",
          label: String(item.session_id),
          provenance: "derived",
          metadata: {
            cross_session_correlation: {
              method: item.method,
              score: item.score,
              strength: item.strength,
              evidence_basis: item.evidence_basis,
              attribution: false,
            },
          },
        });
        nodeIds.add(nodeId);
      }
      const edgeKey = [root.id, nodeId, "cross_session_correlation"].join("|");
      if (!edgeIds.has(edgeKey)) {
        edges.push({
          source: root.id,
          target: nodeId,
          relation: "cross_session_correlation",
          provenance: "derived",
        });
        edgeIds.add(edgeKey);
      }
    });
    state.relationGraph = {...graph, nodes, edges};
    clearGraphPath();
    populateGraphKindFilter(nodes);
    renderRelations(state.relationGraph);
  }

  async function relations(sessionId) {
    const svg = $("relation-graph");
    svg.replaceChildren();
    if (!sessionId) {
      state.relationGraph = null;
      $("relation-count").textContent = "0";
      graphLegend([]);
      return;
    }
    const graph = await safeGet("/api/v1/relations?session_id=" + encodeURIComponent(sessionId));
    if (!graph) return;
    state.relationGraph = graph;
    clearGraphPath();
    populateGraphKindFilter(graph.nodes || []);
    renderRelations(graph);
  }

  async function selectEvent(event, switchView) {
    state.selected = event;
    if (switchView) showView("investigate");
    $("event-empty").hidden = true;
    $("event-details").hidden = false;
    $("investigation-context").hidden = false;
    $("detail-title").textContent = event.event_type || "—";
    $("detail-meta").textContent =
      t("details.sensorTime") + ": " + formatDate(event.timestamp) +
      " · " + t("details.collectorReceived") + ": " + formatDate(event.collector_received_at) +
      " · " + (event.source_ip || "—") + " · " + (event.service || "—") + " · " + (event.honeypot || "—");
    $("detail-observed").textContent = pretty(event.observed);
    $("detail-enrichment").textContent = pretty(event.enrichment);
    $("detail-derived").textContent = pretty(event.derived);
    $("detail-hypotheses").textContent = pretty(event.hypotheses);
    $("detail-collector").textContent = pretty(event.collector);
    renderFeed("event-feed", state.events);
    renderFeed("dashboard-feed", state.events, 12);

    const ip = event.source_ip;
    const sessionId = event.session_id;
    const [eventStudy, session, profile, ti, sessionStudy] = await Promise.all([
      safeGet("/api/v1/study/" + encodeURIComponent(event.id) + "?lang=" + encodeURIComponent(state.lang)),
      sessionId ? safeGet("/api/v1/sessions/" + encodeURIComponent(sessionId)) : Promise.resolve(null),
      ip ? safeGet("/api/v1/ips/" + encodeURIComponent(ip)) : Promise.resolve(null),
      ip ? safeGet("/api/v1/ips/" + encodeURIComponent(ip) + "/threat-intelligence") : Promise.resolve(null),
      sessionId ? safeGet("/api/v1/study/session/" + encodeURIComponent(sessionId) + "?lang=" + encodeURIComponent(state.lang)) : Promise.resolve(null),
    ]);

    state.eventStudy = eventStudy;
    state.session = session;
    state.ipProfile = profile;
    state.sessionStudy = sessionStudy;
    renderEventStudy(eventStudy);
    renderSessionStudy(sessionStudy);
    renderIp(profile);
    renderSession(session);
    renderThreatIntelligence(ti);
    renderSessionTimeline(session);
    await relations(sessionId);
  }

  function caseStatusLabel(status) {
    return t("cases.status." + status);
  }

  function renderCaseList() {
    const root = $("case-list");
    root.replaceChildren();
    if (!state.cases.length) {
      const empty = document.createElement("p");
      empty.className = "mini-empty";
      empty.textContent = t("cases.empty");
      root.append(empty);
      return;
    }
    state.cases.forEach((item) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "case-list-item";
      if (state.selectedCase?.id === item.id) button.classList.add("selected");

      const head = document.createElement("span");
      head.className = "case-list-head";
      const title = document.createElement("strong");
      title.textContent = item.title;
      const severity = severityBadge(item.severity);
      head.append(title, severity);

      const meta = document.createElement("span");
      meta.className = "case-list-meta";
      meta.textContent = caseStatusLabel(item.status) + " · " + formatDate(item.updated_at);

      const tags = document.createElement("span");
      tags.className = "case-list-tags";
      tags.textContent = (item.tags || []).join(" · ");

      button.append(head, meta, tags);
      button.addEventListener("click", () => selectCase(item.id));
      root.append(button);
    });
  }

  function setCaseActionState() {
    const hasCase = Boolean(state.selectedCase?.id);
    $("case-add-event").disabled = !hasCase || !state.selected?.id;
    $("case-add-session").disabled = !hasCase || !state.selected?.session_id;
    $("case-report-json").disabled = !hasCase;
    $("case-report-csv").disabled = !hasCase;
    $("case-report-markdown").disabled = !hasCase;
    $("case-delete").disabled = !hasCase || state.selectedCase?.status !== "closed";
    $("case-note").disabled = !hasCase;
    $("case-note-form").querySelector("button").disabled = !hasCase;
  }

  function resetCaseEditor(seed = []) {
    state.selectedCase = null;
    state.caseSeed = seed;
    $("case-editor-title").textContent = t("cases.newTitle");
    $("case-title").value = "";
    $("case-status").value = "open";
    $("case-severity").value = "info";
    $("case-summary").value = "";
    $("case-tags").value = "";
    if (state.selected && seed.length) {
      $("case-title").value = t("cases.seedTitle")
        .replace("{ip}", state.selected.source_ip || t("common.unknown"))
        .replace("{type}", state.selected.event_type || t("common.event"));
    }
    $("case-evidence").replaceChildren();
    $("case-notes").replaceChildren();
    $("case-history").replaceChildren();
    $("case-evidence-count").textContent = "0";
    setCaseActionState();
    renderCaseList();
  }

  function renderCaseEvidence(items) {
    const root = $("case-evidence");
    root.replaceChildren();
    $("case-evidence-count").textContent = String(items?.length || 0);
    if (!items?.length) {
      const empty = document.createElement("p");
      empty.className = "mini-empty";
      empty.textContent = t("empty.noData");
      root.append(empty);
      return;
    }
    items.forEach((item) => {
      const card = document.createElement("article");
      card.className = "case-evidence-item";
      const head = document.createElement("div");
      head.className = "case-evidence-head";
      const label = document.createElement("strong");
      label.textContent = item.evidence_type + " · " + item.evidence_id;
      const availability = document.createElement("span");
      availability.className = "badge " + (item.available ? "available" : "unavailable");
      availability.textContent = item.available ? t("cases.available") : t("cases.unavailable");
      head.append(label, availability);
      card.append(head);
      if (item.summary) {
        const pre = document.createElement("pre");
        pre.textContent = pretty(item.summary);
        card.append(pre);
      }
      const meta = document.createElement("p");
      meta.className = "muted";
      meta.textContent = formatDate(item.added_at);
      card.append(meta);
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "compact danger-quiet";
      remove.textContent = t("cases.removeEvidence");
      remove.addEventListener("click", async () => {
        if (!state.selectedCase) return;
        try {
          const updated = await requestJSON(
            "/api/v1/cases/" + encodeURIComponent(state.selectedCase.id) + "/evidence/" + encodeURIComponent(item.id),
            "DELETE"
          );
          renderCaseDetail(updated);
          await loadCases();
        } catch (error) {
          console.error("AEGIS case evidence removal failed", error);
        }
      });
      card.append(remove);
      root.append(card);
    });
  }

  function renderCaseNotes(items) {
    const root = $("case-notes");
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

  function renderCaseHistory(items) {
    const root = $("case-history");
    root.replaceChildren();
    if (!items?.length) {
      const empty = document.createElement("p");
      empty.className = "mini-empty";
      empty.textContent = t("empty.noData");
      root.append(empty);
      return;
    }
    const actionKeys = {
      created: "cases.created",
      updated: "cases.updated",
      note_added: "cases.noteAdded",
      evidence_added: "cases.evidenceAdded",
      evidence_removed: "cases.evidenceRemoved",
    };
    items.forEach((item) => {
      const row = document.createElement("div");
      row.className = "case-history-item";
      const head = document.createElement("div");
      const action = document.createElement("strong");
      action.textContent = t(actionKeys[item.action] || item.action);
      const time = document.createElement("time");
      time.textContent = formatDate(item.timestamp);
      head.append(action, time);
      const pre = document.createElement("pre");
      pre.textContent = pretty(item.detail);
      row.append(head, pre);
      root.append(row);
    });
  }

  function renderCaseDetail(item) {
    state.selectedCase = item;
    state.caseSeed = [];
    $("case-editor-title").textContent = item.title;
    $("case-title").value = item.title || "";
    $("case-status").value = item.status || "open";
    $("case-severity").value = item.severity || "info";
    $("case-summary").value = item.summary || "";
    $("case-tags").value = (item.tags || []).join(", ");
    renderCaseEvidence(item.evidence || []);
    renderCaseNotes(item.notes || []);
    renderCaseHistory(item.history || []);
    setCaseActionState();
    renderCaseList();
  }

  async function selectCase(caseId) {
    const item = await safeGet("/api/v1/cases/" + encodeURIComponent(caseId));
    if (item) renderCaseDetail(item);
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
      button.addEventListener("click", async () => {
        const event = await safeGet("/api/v1/events/" + encodeURIComponent(eventId));
        if (!event) return;
        showView("investigate");
        await selectEvent(event, true);
      });
      root.append(button);
    });
  }

  function renderIocDetail(item) {
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

  async function loadIocs() {
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

  async function exportIocs() {
    const params = new URLSearchParams();
    params.set("hours", $("window").value);
    const q = $("ioc-search")?.value.trim() || "";
    const type = $("ioc-type-filter")?.value || "";
    if (q) params.set("q", q);
    if (type) params.set("type", type);
    const response = await fetch("/api/v1/iocs/export.csv?" + params.toString(), {
      headers: apiHeaders({Accept: "text/csv"}),
    });
    if (response.status === 401) {
      showOperatorGate(true);
      return;
    }
    if (!response.ok) throw new Error("HTTP " + response.status);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "aegis-iocs.csv";
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
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
        button.addEventListener("click", async () => {
          const event = await safeGet("/api/v1/events/" + encodeURIComponent(item.id));
          if (!event) return;
          showView("investigate");
          await selectEvent(event, true);
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

  function renderAlertDetail(item) {
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

  async function loadAlerts() {
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

  async function saveAlert() {
    if (!state.selectedAlert?.id) return;
    try {
      const item = await requestJSON(
        "/api/v1/alerts/" + encodeURIComponent(state.selectedAlert.id),
        "PATCH",
        {
          status: $("alert-status").value,
          tags: $("alert-tags").value.split(",").map((item) => item.trim()).filter(Boolean),
        }
      );
      renderAlertDetail(item);
      await loadAlerts();
    } catch (error) {
      console.error("AEGIS alert update failed", error);
    }
  }

  async function addAlertNote(event) {
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

  function seedCaseFromAlert() {
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
    showView("cases");
    resetCaseEditor(seed);
    $("case-title").value = t("alerts.caseTitle")
      .replace("{rule}", state.selectedAlert.rule_id || t("common.unknown"))
      .replace("{ip}", state.selectedAlert.source_ip || t("common.unknown"));
    $("case-severity").value = state.selectedAlert.severity || "medium";
    $("case-tags").value = "alert, " + String(state.selectedAlert.rule_id || "detection");
    loadCases();
  }

  async function loadCases() {
    const params = new URLSearchParams();
    const q = $("case-search").value.trim();
    const status = $("case-status-filter").value;
    if (q) params.set("q", q);
    if (status) params.set("status", status);
    params.set("limit", "150");
    const data = await safeGet("/api/v1/cases?" + params.toString());
    if (!data) return;
    state.cases = data.items || [];
    renderCaseList();
  }

  async function saveCase(event) {
    event.preventDefault();
    const payload = {
      title: $("case-title").value,
      status: $("case-status").value,
      severity: $("case-severity").value,
      summary: $("case-summary").value,
      tags: $("case-tags").value,
    };
    try {
      let item;
      if (state.selectedCase?.id) {
        item = await requestJSON("/api/v1/cases/" + encodeURIComponent(state.selectedCase.id), "PATCH", payload);
      } else {
        item = await requestJSON("/api/v1/cases", "POST", payload);
        for (const evidence of state.caseSeed) {
          item = await requestJSON(
            "/api/v1/cases/" + encodeURIComponent(item.id) + "/evidence",
            "POST",
            evidence
          );
        }
      }
      renderCaseDetail(item);
      await loadCases();
    } catch (error) {
      console.error("AEGIS case save failed", error);
    }
  }

  async function addSelectedEvidence(type) {
    if (!state.selectedCase || !state.selected) return;
    const id = type === "event" ? state.selected.id : state.selected.session_id;
    if (!id) return;
    try {
      const item = await requestJSON(
        "/api/v1/cases/" + encodeURIComponent(state.selectedCase.id) + "/evidence",
        "POST",
        {type, id}
      );
      renderCaseDetail(item);
      await loadCases();
    } catch (error) {
      console.error("AEGIS case evidence link failed", error);
    }
  }

  async function addCaseNote(event) {
    event.preventDefault();
    if (!state.selectedCase) return;
    const body = $("case-note").value.trim();
    if (!body) return;
    try {
      const item = await requestJSON(
        "/api/v1/cases/" + encodeURIComponent(state.selectedCase.id) + "/notes",
        "POST",
        {body}
      );
      $("case-note").value = "";
      renderCaseDetail(item);
      await loadCases();
    } catch (error) {
      console.error("AEGIS case note failed", error);
    }
  }

  function seedCaseFromSelected() {
    if (!state.selected) return;
    const seed = [{type: "event", id: state.selected.id}];
    if (state.selected.session_id) seed.push({type: "session", id: state.selected.session_id});
    showView("cases");
    resetCaseEditor(seed);
    loadCases();
  }

  async function downloadMarkdownReport(url, filename) {
    const separator = url.includes("?") ? "&" : "?";
    const response = await fetch(
      url + separator + "lang=" + encodeURIComponent(state.lang),
      {headers: apiHeaders()}
    );
    if (response.status === 401) {
      showOperatorGate(true);
      return;
    }
    if (!response.ok) throw new Error("HTTP " + response.status);
    downloadBlob(await response.blob(), filename, "text/markdown");
  }

  async function downloadCaseReportJSON() {
    if (!state.selectedCase?.id) return;
    const report = await safeGet("/api/v1/reports/case/" + encodeURIComponent(state.selectedCase.id));
    if (report) downloadBlob(JSON.stringify(report, null, 2), "aegis-" + state.selectedCase.id + ".json", "application/json");
  }

  async function downloadCaseReportMarkdown() {
    if (!state.selectedCase?.id) return;
    const id = state.selectedCase.id;
    await downloadMarkdownReport(
      "/api/v1/reports/case/" + encodeURIComponent(id) + ".md",
      "aegis-" + id + ".md"
    );
  }

  async function downloadCaseReportCSV() {
    if (!state.selectedCase?.id) return;
    const response = await fetch(
      "/api/v1/reports/case/" + encodeURIComponent(state.selectedCase.id) + ".csv",
      {headers: apiHeaders()}
    );
    if (response.status === 401) {
      showOperatorGate(true);
      return;
    }
    if (!response.ok) throw new Error("HTTP " + response.status);
    downloadBlob(await response.blob(), "aegis-" + state.selectedCase.id + ".csv", "text/csv");
  }

  async function deleteSelectedCase() {
    if (!state.selectedCase?.id || state.selectedCase.status !== "closed") return;
    if (!window.confirm(t("cases.deleteConfirm"))) return;
    const caseId = state.selectedCase.id;
    try {
      await requestJSON("/api/v1/cases/" + encodeURIComponent(caseId), "DELETE");
      resetCaseEditor([]);
      await loadCases();
    } catch (error) {
      console.error("AEGIS case deletion failed", error);
    }
  }

  function downloadBlob(content, filename, type) {
    const blob = content instanceof Blob ? content : new Blob([content], {type});
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  async function downloadReportJSON() {
    if (!state.selected?.session_id) return;
    const report = await safeGet("/api/v1/reports/session/" + encodeURIComponent(state.selected.session_id));
    if (report) downloadBlob(JSON.stringify(report, null, 2), "aegis-" + state.selected.session_id + ".json", "application/json");
  }

  async function downloadReportMarkdown() {
    if (!state.selected?.session_id) return;
    const id = state.selected.session_id;
    await downloadMarkdownReport(
      "/api/v1/reports/session/" + encodeURIComponent(id) + ".md",
      "aegis-" + id + ".md"
    );
  }

  async function downloadReportCSV() {
    if (!state.selected?.session_id) return;
    const response = await fetch(
      "/api/v1/reports/session/" + encodeURIComponent(state.selected.session_id) + ".csv",
      {headers: apiHeaders()}
    );
    if (response.status === 401) {
      showOperatorGate(true);
      return;
    }
    if (!response.ok) throw new Error("HTTP " + response.status);
    downloadBlob(await response.blob(), "aegis-" + state.selected.session_id + ".csv", "text/csv");
  }

  function exportStats() {
    if (!state.dashboard) return;
    downloadBlob(JSON.stringify(state.dashboard, null, 2), "aegis-dashboard-stats.json", "application/json");
  }

  async function refresh() {
    const dashboardParams = currentParams();
    const eventsParams = feedParams();
    try {
      const [dashboard, events] = await Promise.all([
        getJSON("/api/v1/dashboard?" + dashboardParams.toString()),
        getJSON("/api/v1/events?" + eventsParams.toString()),
      ]);
      state.dashboard = dashboard;
      state.events = events.items || [];
      state.eventsCursor = events.next_cursor || null;
      state.eventsHasMore = events.has_more === true;
      state.eventsLoadingOlder = false;
      renderEventPagination();
      $("kpi-events").textContent = String(dashboard.totals.events);
      $("kpi-ips").textContent = String(dashboard.totals.unique_source_ip);
      $("kpi-sessions").textContent = String(dashboard.totals.sessions);
      $("kpi-critical").textContent = String(dashboard.totals.critical);
      const quality = dashboard.data_quality || {};
      $("quality-lossy").textContent = String(quality.events_with_lossy_normalization || 0);
      $("quality-truncated").textContent = String(quality.events_with_truncation || 0);
      $("quality-sensor-truncated").textContent = String(quality.events_with_sensor_truncation || 0);
      $("quality-sensor-rejected").textContent = String(quality.events_with_sensor_rejection || 0);
      $("quality-redacted").textContent = String(quality.events_with_credential_redaction || 0);
      $("quality-dropped-keys").textContent = String(quality.dropped_keys || 0);
      const analyticsWarning = $("analytics-warning");
      analyticsWarning.hidden = !dashboard.analysis?.truncated;
      if (dashboard.analysis?.truncated) {
        analyticsWarning.textContent = t("analytics.truncated").replace("{limit}", String(dashboard.analysis.event_limit));
      }
      timeline("timeline", dashboard.timeline);
      timeline("unique-ip-timeline", dashboard.unique_source_ip_timeline);
      map(dashboard.map_points);
      heat(dashboard.heatmap);
      bars("chart-source-ip", dashboard.source_ip, {search: true});
      bars("chart-event-type", dashboard.event_type, {filterKey: "event_type"});
      bars("chart-severity", dashboard.severity, {filterKey: "severity"});
      bars("chart-country", dashboard.country, {filterKey: "country"});
      bars("chart-asn", dashboard.asn, {filterKey: "asn"});
      bars("chart-port", dashboard.destination_port, {filterKey: "destination_port"});
      bars("chart-protocol", dashboard.protocol, {filterKey: "protocol"});
      bars("chart-honeypot", dashboard.honeypot, {filterKey: "honeypot"});
      bars("chart-service", dashboard.service, {filterKey: "service"});
      bars("chart-credentials", dashboard.credentials, {search: true});
      bars("chart-credential-secrets", dashboard.credential_secret_fingerprints, {search: true});
      bars("chart-commands", dashboard.commands, {search: true});
      bars("chart-payloads", dashboard.payloads, {search: true});
      bars("chart-ids", dashboard.ids_alerts, {search: true});
      bars("chart-ioc", dashboard.iocs, {search: true});
      bars("chart-mitre", dashboard.mitre, {search: true});
      bars("chart-cve", dashboard.cves, {search: true});
      renderFeed("event-feed", state.events);
      renderFeed("dashboard-feed", state.events, 12);
    } catch (error) {
      console.error("AEGIS refresh failed", error);
    }
  }

  document.querySelectorAll("[data-view-target]").forEach((button) => {
    button.addEventListener("click", () => {
      showView(button.dataset.viewTarget);
      if (button.dataset.viewTarget === "cases") loadCases();
      if (button.dataset.viewTarget === "alerts") loadAlerts();
      if (button.dataset.viewTarget === "iocs") loadIocs();
    });
  });

  document.querySelectorAll("[data-filter]").forEach((select) => {
    select.addEventListener("change", () => {
      state.filters[select.dataset.filter] = select.value;
      updateFilterCount();
      refresh();
    });
  });

  $("reset-filters").addEventListener("click", () => {
    state.filters = {};
    document.querySelectorAll("[data-filter]").forEach((select) => { select.value = ""; });
    $("global-search").value = "";
    updateFilterCount();
    refresh();
  });

  $("operator-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const candidate = $("operator-key").value.trim();
    state.operatorKey = candidate;
    if (candidate) sessionStorage.setItem("aegis-operator-key", candidate);
    else sessionStorage.removeItem("aegis-operator-key");
    try {
      const status = await getJSON("/api/v1/operator/status");
      if (status.authenticated) {
        hideOperatorGate();
        await loadFilterOptions();
        await loadEnrichmentStatus();
        await loadOperationsStatus();
        await refresh();
      } else {
        showOperatorGate(true);
      }
    } catch {
      showOperatorGate(true);
    }
  });

  $("operator-lock").addEventListener("click", () => {
    state.operatorKey = "";
    sessionStorage.removeItem("aegis-operator-key");
    showOperatorGate(false);
  });

  $("lang-toggle").addEventListener("click", async () => {
    state.lang = state.lang === "it" ? "en" : "it";
    localStorage.setItem("aegis-lang", state.lang);
    i18n();
    renderCaseList();
    renderAlertList();
    renderIocList();
    if (state.selectedIoc) renderIocDetail(state.selectedIoc);
    if (state.selectedAlert) renderAlertDetail(state.selectedAlert);
    if (state.selectedCase) renderCaseDetail(state.selectedCase);
    if (state.selected) await selectEvent(state.selected, false);
  });

  $("window").addEventListener("change", async () => {
    await loadFilterOptions();
    refresh();
    if (document.querySelector('[data-view="iocs"]')?.classList.contains("active")) loadIocs();
  });

  let searchTimer;
  $("global-search").addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(refresh, 250);
  });

  $("graph-kind-filter").addEventListener("change", () => {
    clearGraphPath();
    if (state.relationGraph) renderRelations(state.relationGraph);
  });
  $("graph-depth").addEventListener("change", () => {
    clearGraphPath();
    if (state.relationGraph) renderRelations(state.relationGraph);
  });
  $("graph-evidence-only").addEventListener("change", () => {
    clearGraphPath();
    if (state.relationGraph) renderRelations(state.relationGraph);
  });
  $("graph-expand").addEventListener("click", () => expandGraphCorrelations().catch((error) => console.error("Graph expansion failed", error)));
  $("graph-find-path").addEventListener("click", findGraphPath);
  $("ioc-type-filter").addEventListener("change", loadIocs);
  $("ioc-export").addEventListener("click", () => exportIocs().catch((error) => console.error("IOC export failed", error)));
  let iocSearchTimer;
  $("ioc-search").addEventListener("input", () => {
    clearTimeout(iocSearchTimer);
    iocSearchTimer = setTimeout(loadIocs, 250);
  });
  $("event-load-older").addEventListener("click", loadOlderEvents);
  $("alert-status-filter").addEventListener("change", loadAlerts);
  $("alert-severity-filter").addEventListener("change", loadAlerts);
  $("alert-save").addEventListener("click", saveAlert);
  $("case-from-alert").addEventListener("click", seedCaseFromAlert);
  $("alert-note-form").addEventListener("submit", addAlertNote);
  $("case-from-event").addEventListener("click", seedCaseFromSelected);
  $("case-new").addEventListener("click", () => resetCaseEditor([]));
  $("case-form").addEventListener("submit", saveCase);
  $("case-add-event").addEventListener("click", () => addSelectedEvidence("event"));
  $("case-add-session").addEventListener("click", () => addSelectedEvidence("session"));
  $("case-note-form").addEventListener("submit", addCaseNote);
  $("case-report-json").addEventListener("click", downloadCaseReportJSON);
  $("case-report-csv").addEventListener("click", downloadCaseReportCSV);
  $("case-report-markdown").addEventListener("click", downloadCaseReportMarkdown);
  $("case-delete").addEventListener("click", deleteSelectedCase);
  $("case-status-filter").addEventListener("change", loadCases);
  let caseSearchTimer;
  $("case-search").addEventListener("input", () => {
    clearTimeout(caseSearchTimer);
    caseSearchTimer = setTimeout(loadCases, 250);
  });

  $("open-relations").addEventListener("click", () => {
    showView("relations");
    if (state.selected?.session_id) relations(state.selected.session_id);
  });
  $("open-study").addEventListener("click", () => showView("study"));
  $("report-json").addEventListener("click", downloadReportJSON);
  $("report-csv").addEventListener("click", downloadReportCSV);
  $("report-markdown").addEventListener("click", downloadReportMarkdown);
  $("export-stats").addEventListener("click", exportStats);
  $("map-zoom-in").addEventListener("click", () => zoomMap(.75));
  $("map-zoom-out").addEventListener("click", () => zoomMap(1.33));
  $("map-reset").addEventListener("click", () => {
    state.mapBox = [0, 0, 800, 390];
    applyMapBox();
  });

  async function bootstrap() {
    i18n();
    applyMapBox();
    updateFilterCount();
    resetCaseEditor([]);
    try {
      const status = await getJSON("/api/v1/operator/status");
      if (status.required && !status.authenticated) {
        showOperatorGate(Boolean(state.operatorKey));
        return;
      }
      hideOperatorGate();
      await loadFilterOptions();
      await loadEnrichmentStatus();
      await loadOperationsStatus();
      await refresh();
    } catch (error) {
      console.error("AEGIS bootstrap failed", error);
      showOperatorGate(Boolean(state.operatorKey));
    }
  }

  bootstrap();
  window.setInterval(() => {
    if (!document.hidden && $("operator-gate").hidden) refresh();
  }, 5000);
  window.setInterval(() => {
    if (!document.hidden && $("operator-gate").hidden) loadOperationsStatus();
  }, 30000);
})();