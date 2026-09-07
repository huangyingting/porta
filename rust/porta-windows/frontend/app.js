const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const state = {
  snapshot: null,
  view: "home",
  editorProfile: null,
  deleteArmed: false,
  downloadHistory: Array(54).fill(0),
  uploadHistory: Array(54).fill(0),
  lastTraffic: "",
  clearArmed: false,
  clearTimer: null,
  messageTimer: null,
};

const $ = (id) => document.getElementById(id);
const chartHeight = 84;

async function call(name, ...args) {
  try {
    const commands = {
      Snapshot: ["snapshot", {}],
      SelectProfile: ["select_profile", { id: args[0] }],
      SaveProfile: ["save_profile", { input: args[0] }],
      DeleteProfile: ["delete_profile", { id: args[0] }],
      Connect: ["connect", { id: args[0] }],
      Disconnect: ["disconnect", {}],
      RestoreNetwork: ["restore_network", {}],
      ClearActivity: ["clear_activity", {}],
      SaveActivityLog: ["save_activity_log", {}],
      OpenLogFolder: ["open_log_folder", {}],
    };
    const [command, parameters] = commands[name];
    const result = await invoke(command, parameters);
    hideError();
    return result;
  } catch (error) {
    showError(error?.message || String(error));
    throw error;
  }
}

function showError(message) {
  $("error-message").textContent = message;
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
  $("add-action").classList.toggle(
    "hidden",
    state.view !== "home" || Boolean(state.snapshot?.startupBlocked),
  );
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
  $("status-title").textContent = snapshot.status;
  $("status-detail").textContent = snapshot.detail;
  $("status-dot").className = "status-dot " + (snapshot.tone || "offline");
  $("status-card").classList.toggle("startup-blocked", snapshot.startupBlocked);
  $("traffic-card").classList.toggle("hidden", snapshot.startupBlocked);
  $("profiles-section").classList.toggle("hidden", snapshot.startupBlocked);
  $("home-footer").classList.toggle("hidden", snapshot.startupBlocked);
  $("add-action").classList.toggle("hidden", snapshot.startupBlocked || state.view !== "home");
  $("traffic-state").textContent = snapshot.running ? "LIVE" : "IDLE";
  $("traffic-state").classList.toggle("active", snapshot.running);
  $("download-rate").textContent = formatRate(snapshot.downloadRate);
  $("upload-rate").textContent = formatRate(snapshot.uploadRate);
  $("connection-address").textContent = snapshot.address || "No address";
  $("connection-total").textContent =
    `${formatBytes(snapshot.bytesDownloaded)} received · ${formatBytes(snapshot.bytesUploaded)} sent`;
  $("activity-log").textContent = snapshot.activity?.length
    ? snapshot.activity.join("\n")
    : "No connection activity yet.";
  const hasActivity = Boolean(snapshot.activity?.length);
  $("save-log-action").disabled = !hasActivity;
  $("clear-log-action").disabled = !hasActivity;
  $("restore-action").disabled =
    !snapshot.recoveryAvailable || snapshot.running || snapshot.restoring;

  const primary = $("primary-connect");
  primary.textContent = snapshot.disconnecting
    ? "Disconnecting…"
    : snapshot.running
      ? "Disconnect"
      : "Connect";
  primary.disabled =
    snapshot.startupBlocked || snapshot.restoring || snapshot.disconnecting ||
    (!snapshot.running && !snapshot.selectedProfileId);
  primary.classList.toggle("hidden", snapshot.startupBlocked);

  const trafficKey = `${snapshot.downloadRate}:${snapshot.uploadRate}:${snapshot.running}`;
  if (trafficKey !== state.lastTraffic) {
    state.lastTraffic = trafficKey;
    state.downloadHistory.shift();
    state.uploadHistory.shift();
    state.downloadHistory.push(snapshot.running ? snapshot.downloadRate : 0);
    state.uploadHistory.push(snapshot.running ? snapshot.uploadRate : 0);
  }
  if (!previous || (!previous.connected && snapshot.connected)) {
    state.downloadHistory.fill(snapshot.downloadRate || 0);
    state.uploadHistory.fill(snapshot.uploadRate || 0);
  }
  renderProfiles();
  drawChart();
  updateDuration();
}

function renderProfiles() {
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
    select.setAttribute("aria-label", `Select ${profile.name}`);
    select.disabled = state.snapshot.running && !profile.active;
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
    status.textContent = profile.status;
    copy.append(name, server, status);
    select.append(avatar, copy);

    const actions = document.createElement("div");
    actions.className = "profile-actions";
    const edit = document.createElement("button");
    edit.type = "button";
    edit.className = "edit-action";
    edit.textContent = "Edit";
    edit.disabled = state.snapshot.running || state.snapshot.restoring;
    edit.setAttribute("aria-label", `Edit ${profile.name}`);
    edit.addEventListener("click", () => openEditor(profile));
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "switch-action";
    toggle.setAttribute("role", "switch");
    toggle.setAttribute("aria-label", profile.active ? `Disconnect ${profile.name}` : `Connect ${profile.name}`);
    toggle.setAttribute("aria-checked", profile.active ? "true" : "false");
    toggle.disabled =
      state.snapshot.restoring ||
      (state.snapshot.running && !profile.active);
    toggle.addEventListener("click", () => toggleProfile(profile));
    actions.append(edit, toggle);
    card.append(select, actions);
    list.append(card);
  }
}

async function selectProfile(id) {
  const snapshot = await call("SelectProfile", id);
  applySnapshot(snapshot);
}

async function toggleProfile(profile) {
  if (profile.active && state.snapshot.running) {
    await call("Disconnect");
    return;
  }
  if (!profile.selected) {
    const snapshot = await call("SelectProfile", profile.id);
    applySnapshot(snapshot);
  }
  await call("Connect", profile.id);
}

function openEditor(profile = null) {
  state.editorProfile = profile;
  state.deleteArmed = false;
  $("editor-title").textContent = profile ? "Edit profile" : "Add profile";
  $("profile-id").value = profile?.id || "";
  $("profile-name").value = profile?.name || "";
  $("profile-server").value = profile?.serverUrl || "https://";
  $("profile-transport").value = profile?.transport || "auto";
  $("profile-token").value = "";
  $("profile-token").required = !profile;
  $("token-hint").textContent = profile
    ? "Leave blank to keep the protected token"
    : "Required for a new profile";
  $("delete-profile").classList.toggle("hidden", !profile);
  $("delete-profile").classList.remove("confirm");
  $("delete-profile").textContent = "Delete";
  setView("editor");
  requestAnimationFrame(() => $("profile-name").focus());
}

function closeEditor() {
  setView("home");
  state.editorProfile = null;
  state.deleteArmed = false;
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
  $("clear-log-action").textContent = "Clear";
  $("clear-log-action").classList.remove("confirm");
}

async function clearActivity() {
  if (!state.clearArmed) {
    state.clearArmed = true;
    $("clear-log-action").textContent = "Confirm clear";
    $("clear-log-action").classList.add("confirm");
    state.clearTimer = window.setTimeout(resetClearAction, 3500);
    return;
  }
  await call("ClearActivity");
  resetClearAction();
  showActivityMessage("Activity log cleared.");
}

async function saveActivity() {
  const path = await call("SaveActivityLog");
  if (path) showActivityMessage(`Saved to ${path}`);
}

async function openLogFolder() {
  const path = await call("OpenLogFolder");
  if (path) showActivityMessage(`Opened ${path}`);
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
  const snapshot = await call("SaveProfile", input);
  applySnapshot(snapshot);
  closeEditor();
}

async function deleteProfile() {
  if (!state.editorProfile) return;
  if (!state.deleteArmed) {
    state.deleteArmed = true;
    $("delete-profile").classList.add("confirm");
    $("delete-profile").textContent = "Confirm delete";
    return;
  }
  const snapshot = await call("DeleteProfile", state.editorProfile.id);
  applySnapshot(snapshot);
  closeEditor();
}

function formatBytes(value = 0) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = Number(value) || 0;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit++;
  }
  return unit === 0 ? `${Math.round(size)} ${units[unit]}` : `${size.toFixed(1)} ${units[unit]}`;
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
  await listen("porta:snapshot", (event) => applySnapshot(event.payload));
  await listen("porta:view", (event) => setView(event.payload));
  applySnapshot(await call("Snapshot"));
}

$("activity-action").addEventListener("click", () => setView("activity"));
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
  if (state.snapshot?.running) await call("Disconnect");
  else await call("Connect", state.snapshot?.selectedProfileId || "");
});
$("restore-action").addEventListener("click", async () => {
  await call("RestoreNetwork");
});
$("clear-log-action").addEventListener("click", clearActivity);
$("save-log-action").addEventListener("click", saveActivity);
$("open-log-action").addEventListener("click", openLogFolder);
window.addEventListener("resize", drawChart);
window.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && state.view === "editor") closeEditor();
});
window.setInterval(updateDuration, 1000);
initialise();
