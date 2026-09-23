import { Call, Events } from "/wails/runtime.js";
import { initialLanguage, translate } from "./i18n.js";

const method = "main.DesktopController.";
const state = {
  snapshot: null,
  view: "home",
  language: initialLanguage(),
  editorProfile: null,
  deleteArmed: false,
  deleteTimer: null,
  pendingAction: "",
  profileSignature: "",
  activitySignature: "",
  downloadHistory: Array(54).fill(0),
  uploadHistory: Array(54).fill(0),
  clearArmed: false,
  clearTimer: null,
  messageTimer: null,
};

const $ = (id) => document.getElementById(id);
const chartHeight = 84;
const t = (message, values) => translate(state.language, message, values);

function setLanguage(language, persist = true) {
  state.language = language === "zh-CN" ? "zh-CN" : "en";
  if (persist) {
    try { localStorage.setItem("porta.language", state.language); } catch (_) {}
  }
  document.documentElement.lang = state.language;
  document.querySelectorAll("[data-i18n]").forEach((element) => {
    element.dataset.i18n ||= element.textContent.trim();
    element.textContent = t(element.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-aria]").forEach((element) => {
    element.dataset.i18nAria ||= element.getAttribute("aria-label");
    element.setAttribute("aria-label", t(element.dataset.i18nAria));
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((element) => {
    element.dataset.i18nPlaceholder ||= element.placeholder;
    element.placeholder = t(element.dataset.i18nPlaceholder);
  });
  $("language-action").textContent = state.language === "en" ? "中" : "EN";
  $("language-action").setAttribute("aria-label", state.language === "en" ? "切换到简体中文" : "Switch to English");
  resetClearAction();
  resetDeleteAction();
  updateEditorLabels();
  state.profileSignature = "";
  state.activitySignature = "";
  if (state.snapshot) applySnapshot(state.snapshot);
}

async function performAction(name, action) {
  if (state.pendingAction) return;
  state.pendingAction = name;
  updatePendingState();
  try {
    return await action();
  } catch (error) {
    showError(error?.message || String(error));
    if (state.view === "editor") {
      $("editor-error").textContent = t(error?.message || String(error));
      $("editor-error").classList.remove("hidden");
    }
  } finally {
    state.pendingAction = "";
    updatePendingState();
  }
}

function updatePendingState() {
  const snapshot = state.snapshot;
  const busy = Boolean(state.pendingAction);
  $("profile-form").querySelectorAll("input, select, button").forEach((element) => { element.disabled = busy; });
  $("language-action").disabled = busy;
  $("add-action").disabled = busy || snapshot?.running || snapshot?.restoring || snapshot?.startupBlocked;
  $("empty-add").disabled = $("add-action").disabled;
  $("primary-connect").disabled = busy || snapshot?.startupBlocked || snapshot?.restoring ||
    snapshot?.disconnecting || (!snapshot?.running && !snapshot?.selectedProfileId);
  $("restore-action").disabled = busy || snapshot?.startupBlocked || !snapshot?.recoveryAvailable ||
    snapshot?.running || snapshot?.restoring;
  $("save-log-action").disabled = busy || !snapshot?.activity?.length;
  $("clear-log-action").disabled = busy || !snapshot?.activity?.length;
  $("open-log-action").disabled = busy;
  renderProfiles();
}

async function call(name, ...args) {
  try {
    const result = await Call.ByName(method + name, ...args);
    hideError();
    return result;
  } catch (error) {
    showError(t(error?.message || String(error)));
    throw error;
  }
}

function showError(message) {
  $("error-message").textContent = t(message);
  $("error-banner").classList.remove("hidden");
}

function hideError() {
  $("error-banner").classList.add("hidden");
}

function setView(view) {
  state.view = view === "activity" || view === "editor" ? view : "home";
  $("home-view").classList.toggle("hidden", state.view !== "home");
  $("activity-view").classList.toggle("hidden", state.view !== "activity");
  $("editor").classList.toggle("hidden", state.view !== "editor");
  $("activity-action").classList.toggle("hidden", state.view !== "home");
  $("home-action").classList.toggle("hidden", state.view === "home");
  $("add-action").classList.toggle("hidden", state.view !== "home" || Boolean(state.snapshot?.startupBlocked));
  if (state.view === "activity") {
    requestAnimationFrame(() => {
      const log = $("activity-log");
      log.scrollTop = log.scrollHeight;
    });
  }
}

function applySnapshot(snapshot) {
  if (!snapshot) return;
  const previous = state.snapshot;
  state.snapshot = snapshot;
  $("version").textContent = "v" + snapshot.version;
  $("status-title").textContent = t(snapshot.status);
  $("status-detail").textContent = localizedDetail(snapshot);
  $("status-dot").className = "status-dot " + (snapshot.tone || "offline");
  $("traffic-state").textContent = t(snapshot.running ? "LIVE" : "IDLE");
  $("traffic-state").classList.toggle("active", snapshot.running);
  $("download-rate").textContent = formatRate(snapshot.downloadRate);
  $("upload-rate").textContent = formatRate(snapshot.uploadRate);
  $("connection-address").textContent = snapshot.address || t("No address");
  $("connection-total").textContent =
    t("{received} received · {sent} sent", { received: formatBytes(snapshot.bytesDownloaded), sent: formatBytes(snapshot.bytesUploaded) });
  const activity = snapshot.activity?.length ? snapshot.activity.join("\n") : t("No connection activity yet.");
  if (activity !== state.activitySignature) {
    state.activitySignature = activity;
    $("activity-log").textContent = activity;
  }
  $("traffic-card").classList.toggle("hidden", Boolean(snapshot.startupBlocked));
  $("profiles-section").classList.toggle("hidden", Boolean(snapshot.startupBlocked));
  $("add-action").classList.toggle("hidden", Boolean(snapshot.startupBlocked) || state.view !== "home");
  $("transport-badge").textContent = (snapshot.transport || "").toUpperCase();
  $("transport-badge").classList.toggle("hidden", !snapshot.connected || !snapshot.transport);

  const primary = $("primary-connect");
  primary.textContent = snapshot.disconnecting
    ? t("Disconnecting…")
    : snapshot.running
      ? t("Disconnect")
      : t("Connect");
  if (!previous || !snapshot.running || (!previous.connected && snapshot.connected)) {
    state.downloadHistory.fill(0);
    state.uploadHistory.fill(0);
  }
  updatePendingState();
  drawChart();
  updateDuration();
}

function localizedDetail(snapshot) {
  if (snapshot.startupBlocked) return snapshot.detail;
  switch (snapshot.status) {
    case "Disconnected":
      if (snapshot.detail === "Normal network access has been restored.") return t(snapshot.detail);
      return t(snapshot.profiles?.length ? "Choose a profile to connect securely." : "Add a profile to connect securely.");
    case "Connecting": return t("Establishing a secure tunnel...");
    case "Configuring network": return t("Applying private routes, DNS, and tunnel MTU...");
    case "Connected":
      return t(snapshot.transport === "h3" ? "HTTP/3 MASQUE · fast and resilient · MTU {mtu}" :
        snapshot.transport === "h2" ? "4-lane HTTP/2 fallback · encrypted · MTU {mtu}" :
          "Encrypted tunnel active · MTU {mtu}", { mtu: snapshot.mtu });
    case "Reconnecting": return t("The network changed; restoring the secure tunnel...");
    case "Disconnecting":
    case "Restoring network": return t("Restoring normal network access...");
    case "Network recovery available": return t("Reconnect to resume, or restore normal connectivity.");
    case "Recovering network": return t("Resuming retained fail-closed protection...");
    default: return t(snapshot.detail);
  }
}

function applyTraffic(traffic) {
  if (!traffic || !state.snapshot || !state.snapshot.connected || state.snapshot.disconnecting) return;
  const snapshot = state.snapshot;
  Object.assign(snapshot, traffic);
  $("download-rate").textContent = formatRate(snapshot.downloadRate);
  $("upload-rate").textContent = formatRate(snapshot.uploadRate);
  $("connection-total").textContent = t("{received} received · {sent} sent", {
    received: formatBytes(snapshot.bytesDownloaded), sent: formatBytes(snapshot.bytesUploaded),
  });
  // Every sample advances time, including constant rates and idle samples.
  state.downloadHistory.shift();
  state.uploadHistory.shift();
  state.downloadHistory.push(Number(snapshot.downloadRate) || 0);
  state.uploadHistory.push(Number(snapshot.uploadRate) || 0);
  drawChart();
}

function renderProfiles() {
  const signature = JSON.stringify([state.language, state.pendingAction, state.snapshot?.running,
    state.snapshot?.restoring, state.snapshot?.disconnecting, state.snapshot?.profiles]);
  if (signature === state.profileSignature) return;
  state.profileSignature = signature;
  const list = $("profiles");
  list.replaceChildren();
  const profiles = state.snapshot?.profiles || [];
  $("empty-state").classList.toggle("hidden", profiles.length !== 0);
  list.classList.toggle("hidden", profiles.length === 0);
  for (const profile of profiles) {
    const card = document.createElement("article");
    card.className = "profile-card";
    if (profile.selected) card.classList.add("selected");
    if (profile.active) card.classList.add("active");

    const select = document.createElement("button");
    select.type = "button";
    select.className = "profile-main";
    select.setAttribute("aria-label", t("Select {name}", { name: profile.name }));
    select.disabled = Boolean(state.pendingAction) || state.snapshot.restoring || (state.snapshot.running && !profile.active);
    select.addEventListener("click", () => selectProfile(profile.id));

    const avatar = document.createElement("span");
    avatar.className = "profile-avatar";
    avatar.textContent = firstLetter(profile.name);
    const copy = document.createElement("span");
    copy.className = "profile-copy";
    const name = document.createElement("strong");
    name.textContent = profile.name;
    const server = document.createElement("span");
    server.className = "server";
    server.textContent = cleanServer(profile.serverUrl);
    const status = document.createElement("span");
    status.className = "profile-status";
    status.textContent = t(profile.active && state.snapshot.disconnecting ? "Disconnecting" : profile.status);
    copy.append(name, server, status);
    select.append(avatar, copy);

    const actions = document.createElement("div");
    actions.className = "profile-actions";
    const edit = document.createElement("button");
    edit.type = "button";
    edit.className = "edit-action";
    edit.textContent = t("Edit");
    edit.disabled = Boolean(state.pendingAction) || state.snapshot.running || state.snapshot.restoring;
    edit.setAttribute("aria-label", t("Edit {name}", { name: profile.name }));
    edit.addEventListener("click", () => openEditor(profile));
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "switch-action";
    toggle.setAttribute("role", "switch");
    toggle.setAttribute("aria-label", t(profile.active ? "Disconnect {name}" : "Connect {name}", { name: profile.name }));
    toggle.setAttribute("aria-checked", profile.active ? "true" : "false");
    toggle.disabled =
      Boolean(state.pendingAction) || state.snapshot.restoring || state.snapshot.disconnecting ||
      (state.snapshot.running && !profile.active);
    toggle.addEventListener("click", () => toggleProfile(profile));
    actions.append(edit, toggle);
    card.append(select, actions);
    list.append(card);
  }
}

async function selectProfile(id) {
  await performAction("select", async () => applySnapshot(await call("SelectProfile", id)));
}

async function toggleProfile(profile) {
  await performAction("toggle", async () => {
  if (profile.active && state.snapshot.running) {
    await call("Disconnect");
    return;
  }
  if (!profile.selected) {
    const snapshot = await call("SelectProfile", profile.id);
    applySnapshot(snapshot);
  }
  await call("Connect", profile.id);
  });
}

function openEditor(profile = null) {
  if (state.pendingAction || state.snapshot?.running || state.snapshot?.restoring || state.snapshot?.startupBlocked) return;
  state.editorProfile = profile;
  resetDeleteAction();
  $("profile-id").value = profile?.id || "";
  $("profile-name").value = profile?.name || "";
  $("profile-server").value = profile?.serverUrl || "https://";
  $("profile-transport").value = profile?.transport || "auto";
  $("profile-token").value = "";
  $("profile-token").required = !profile;
  updateEditorLabels();
  $("editor-error").classList.add("hidden");
  $("delete-profile").classList.toggle("hidden", !profile);
  $("delete-profile").classList.remove("confirm");
  setView("editor");
  requestAnimationFrame(() => $("profile-name").focus());
}

function updateEditorLabels() {
  $("editor-title").textContent = t(state.editorProfile ? "Edit profile" : "Add profile");
  $("token-hint").textContent = t(state.editorProfile ? "Leave blank to keep the protected token" : "Required for a new profile");
}

function closeEditor() {
  if (state.pendingAction) return;
  setView("home");
  state.editorProfile = null;
  $("profile-token").value = "";
  resetDeleteAction();
}

function showActivityMessage(message) {
  window.clearTimeout(state.messageTimer);
  $("activity-message").textContent = message;
  $("activity-message").classList.toggle("hidden", !message);
  if (message) {
    state.messageTimer = window.setTimeout(() => {
      $("activity-message").classList.add("hidden");
    }, 6000);
  }
}

function resetClearAction() {
  window.clearTimeout(state.clearTimer);
  state.clearArmed = false;
  $("clear-log-action").textContent = t("Clear");
  $("clear-log-action").classList.remove("confirm");
}

function resetDeleteAction() {
  window.clearTimeout(state.deleteTimer);
  state.deleteArmed = false;
  $("delete-profile").textContent = t("Delete");
  $("delete-profile").classList.remove("confirm");
}

async function clearActivity() {
  if (!state.clearArmed) {
    state.clearArmed = true;
    $("clear-log-action").textContent = t("Confirm clear");
    $("clear-log-action").classList.add("confirm");
    state.clearTimer = window.setTimeout(resetClearAction, 3500);
    return;
  }
  await performAction("clear", async () => {
    await call("ClearActivity");
    resetClearAction();
    showActivityMessage(t("Activity log cleared."));
  });
}

async function saveActivity() {
  await performAction("export", async () => {
    const path = await call("SaveActivityLog");
    if (path) showActivityMessage(t("Saved to {path}", { path }));
  });
}

async function openLogFolder() {
  await performAction("folder", async () => {
    const path = await call("OpenLogFolder");
    if (path) showActivityMessage(t("Opened {path}", { path }));
  });
}

async function saveProfile(event) {
  event.preventDefault();
  const input = {
    id: $("profile-id").value,
    name: $("profile-name").value,
    serverUrl: $("profile-server").value,
    transport: $("profile-transport").value,
    token: $("profile-token").value,
  };
  const invalid = validateProfileInput(input);
  if (invalid) {
    $("editor-error").textContent = t(invalid.message);
    $("editor-error").classList.remove("hidden");
    $(invalid.field).focus();
    return;
  }
  const saved = await performAction("save", async () => {
    applySnapshot(await call("SaveProfile", input));
    return true;
  });
  if (saved) closeEditor();
}

function validateProfileInput(input) {
  if (!input.name.trim()) return { field: "profile-name", message: "Enter a profile name." };
  try {
    const url = new URL(input.serverUrl.trim());
    if (url.protocol !== "https:" || !url.hostname || url.username || url.password ||
      (url.pathname !== "" && url.pathname !== "/") || input.serverUrl.includes("?") || input.serverUrl.includes("#")) {
      return { field: "profile-server", message: "The gateway must be an HTTPS origin without a path, query, or credentials." };
    }
  } catch (_) {
    return { field: "profile-server", message: "Enter a valid HTTPS gateway URL." };
  }
  if (!input.id && !input.token.trim()) return { field: "profile-token", message: "Enter an access token." };
  return null;
}

async function deleteProfile() {
  if (!state.editorProfile) return;
  if (!state.deleteArmed) {
    state.deleteArmed = true;
    $("delete-profile").classList.add("confirm");
    $("delete-profile").textContent = t("Confirm delete");
    state.deleteTimer = window.setTimeout(resetDeleteAction, 3500);
    return;
  }
  const deleted = await performAction("delete", async () => {
    applySnapshot(await call("DeleteProfile", state.editorProfile.id));
    return true;
  });
  if (deleted) closeEditor();
}

function formatBytes(value = 0) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = Number(value) || 0;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit++;
  }
  return `${size.toLocaleString(state.language, { minimumFractionDigits: unit === 0 ? 0 : 1, maximumFractionDigits: unit === 0 ? 0 : 1 })} ${units[unit]}`;
}

function formatRate(value = 0) {
  return `${formatBytes(value)}/s`;
}

function cleanServer(value = "") {
  return value.replace(/^https:\/\//i, "").replace(/\/$/, "");
}

function firstLetter(value = "") {
  return Array.from(value.trim())[0]?.toUpperCase() || "P";
}

function updateDuration() {
  const connectedAt = state.snapshot?.connectedAt;
  if (!connectedAt) {
    $("connection-duration").textContent = "00:00:00";
    return;
  }
  const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(connectedAt)) / 1000));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor(seconds / 60) % 60;
  const remainder = seconds % 60;
  $("connection-duration").textContent =
    [hours, minutes, remainder].map((value) => String(value).padStart(2, "0")).join(":");
}

function drawChart() {
  const canvas = $("traffic-chart");
  const rect = canvas.getBoundingClientRect();
  if (!rect.width) return;
  const scale = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, Math.round(rect.width * scale));
  canvas.height = Math.max(1, Math.round(chartHeight * scale));
  const context = canvas.getContext("2d");
  context.scale(scale, scale);
  const width = rect.width;
  const height = chartHeight;
  context.clearRect(0, 0, width, height);
  context.strokeStyle = "rgba(148, 163, 184, .10)";
  context.lineWidth = 1;
  for (let row = 1; row < 4; row++) {
    const y = Math.round((height / 4) * row) + .5;
    context.beginPath();
    context.moveTo(0, y);
    context.lineTo(width, y);
    context.stroke();
  }
  const maximum = Math.max(1, ...state.downloadHistory, ...state.uploadHistory);
  drawSeries(context, state.downloadHistory, maximum, width, height, "#6ee7b7", "rgba(110,231,183,.12)");
  drawSeries(context, state.uploadHistory, maximum, width, height, "#60a5fa", "rgba(96,165,250,.06)");
}

function drawSeries(context, values, maximum, width, height, stroke, fill) {
  const points = values.map((value, index) => ({
    x: (index / Math.max(1, values.length - 1)) * width,
    y: height - 8 - (value / maximum) * (height - 18),
  }));
  context.beginPath();
  points.forEach((point, index) => {
    if (index === 0) context.moveTo(point.x, point.y);
    else context.lineTo(point.x, point.y);
  });
  context.lineTo(width, height);
  context.lineTo(0, height);
  context.closePath();
  context.fillStyle = fill;
  context.fill();
  context.beginPath();
  points.forEach((point, index) => {
    if (index === 0) context.moveTo(point.x, point.y);
    else context.lineTo(point.x, point.y);
  });
  context.strokeStyle = stroke;
  context.lineWidth = 2;
  context.lineJoin = "round";
  context.lineCap = "round";
  context.stroke();
}

async function initialise() {
  setLanguage(state.language, false);
  Events.On("porta:snapshot", (event) => applySnapshot(event.data));
  Events.On("porta:traffic", (event) => applyTraffic(event.data));
  Events.On("porta:view", (event) => setView(event.data));
  applySnapshot(await call("Snapshot"));
}

$("activity-action").addEventListener("click", () => setView("activity"));
$("language-action").addEventListener("click", () => setLanguage(state.language === "en" ? "zh-CN" : "en"));
$("home-action").addEventListener("click", () => {
  if (state.view === "editor") closeEditor();
  else setView("home");
});
$("add-action").addEventListener("click", () => openEditor());
$("empty-add").addEventListener("click", () => openEditor());
$("editor-close").addEventListener("click", closeEditor);
$("cancel-edit").addEventListener("click", closeEditor);
$("profile-form").addEventListener("submit", saveProfile);
$("delete-profile").addEventListener("click", deleteProfile);
$("dismiss-error").addEventListener("click", hideError);
$("primary-connect").addEventListener("click", async () => {
  await performAction("toggle", async () => {
    if (state.snapshot?.running) await call("Disconnect");
    else await call("Connect", state.snapshot?.selectedProfileId || "");
  });
});
$("restore-action").addEventListener("click", async () => {
  await performAction("restore", () => call("RestoreNetwork"));
});
$("clear-log-action").addEventListener("click", clearActivity);
$("save-log-action").addEventListener("click", saveActivity);
$("open-log-action").addEventListener("click", openLogFolder);
window.addEventListener("resize", drawChart);
window.addEventListener("keydown", (event) => {
  if (event.key !== "Escape" || state.pendingAction) return;
  if (state.view === "editor") closeEditor();
  else setView("home");
});
window.setInterval(updateDuration, 1000);
initialise().catch((error) => showError(error?.message || String(error)));
