const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const messages = {
  en: {
    tagline: "Private access, simply.",
    back: "Back",
    openLog: "Open connection log",
    switchToEnglish: "Switch to English",
    switchToChinese: "切换到简体中文",
    addProfile: "Add profile",
    connection: "Connection",
    traffic: "Real-time traffic",
    download: "Download",
    upload: "Upload",
    address: "Address",
    duration: "Duration",
    total: "Total",
    profiles: "VPN profiles",
    chooseConnection: "Choose a connection",
    emptyTitle: "Add your first profile",
    emptyDetail: "Enter the gateway and access token from your administrator.",
    log: "Log",
    connectionLog: "Connection log",
    logDetail: "Recent activity stays on this device.",
    restoreNetwork: "Restore network",
    export: "Export",
    clear: "Clear",
    confirmClear: "Confirm clear",
    logEmpty: "No activity yet.",
    profile: "Profile",
    editorDetail: "Porta automatically chooses the fastest secure transport.",
    profileName: "Profile name",
    profileNamePlaceholder: "Home, work, travel…",
    gateway: "Gateway URL",
    accessToken: "Access token",
    accessTokenPlaceholder: "Paste the token from your administrator",
    tokenHelpNew: "Stored securely for this Windows account.",
    tokenHelpEdit: "Leave blank to keep the current protected token.",
    delete: "Delete",
    confirmDelete: "Confirm delete",
    cancel: "Cancel",
    save: "Save",
    dismiss: "Dismiss",
    editProfile: "Edit {name}",
    selectProfile: "Select {name}",
    connectProfile: "Connect {name}",
    disconnectProfile: "Disconnect {name}",
    addProfileTitle: "Add profile",
    editProfileTitle: "Edit profile",
    idle: "Idle",
    live: "Live",
    noAddress: "—",
    receivedSent: "{received} ↓ · {sent} ↑",
    savedTo: "Log saved to {path}",
    logCleared: "Connection log cleared.",
    disconnected: "Disconnected",
    ready: "Ready",
    connecting: "Connecting",
    connected: "Connected",
    reconnecting: "Reconnecting",
    disconnecting: "Disconnecting",
    configuringNetwork: "Configuring network",
    recoveringNetwork: "Recovering network",
    restoringNetwork: "Restoring network",
    recoveryAvailable: "Network recovery available",
    connectionError: "Connection error",
    recoveryFailed: "Network recovery failed",
    actionRequired: "Action required",
    selectedProfile: "Selected profile",
    autoReconnect: "Auto reconnect enabled",
    chooseProfile: "Choose a profile to connect.",
    addProfileDetail: "Add a profile to connect.",
    profileReady: "{name} · {server}",
    establishingTunnel: "Establishing a secure tunnel…",
    configuringTunnel: "Applying private routes, DNS, and tunnel MTU…",
    connectedH3: "HTTP/3 MASQUE · fast and resilient · MTU {mtu}",
    connectedH2: "4-lane HTTP/2 fallback · encrypted · MTU {mtu}",
    connectedAuto: "Encrypted tunnel active · MTU {mtu}",
    reconnectingDetail: "The network changed; restoring the secure tunnel…",
    disconnectingDetail: "Restoring normal network access…",
    recoveryDetail: "Reconnect to resume protection, or restore normal connectivity.",
    recoveryActive: "Resuming retained fail-closed protection…",
    networkRestored: "Normal network access has been restored.",
    recoveryPending: "Network recovery remains pending.",
    invalidServer: "Enter a valid HTTPS gateway URL.",
    httpsOriginRequired: "The gateway must be an HTTPS origin without a path, query, or credentials.",
    nameRequired: "Enter a profile name.",
    tokenRequired: "Enter an access token.",
  },
  "zh-CN": {
    tagline: "简单、安全地访问私有网络。",
    back: "返回",
    openLog: "打开连接日志",
    switchToEnglish: "Switch to English",
    switchToChinese: "切换到简体中文",
    addProfile: "添加配置",
    connection: "连接",
    traffic: "实时流量",
    download: "下载",
    upload: "上传",
    address: "地址",
    duration: "时长",
    total: "总计",
    profiles: "VPN 配置",
    chooseConnection: "选择连接",
    emptyTitle: "添加第一个配置",
    emptyDetail: "输入管理员提供的网关地址和访问令牌。",
    log: "日志",
    connectionLog: "连接日志",
    logDetail: "最近的活动仅保存在此设备上。",
    restoreNetwork: "恢复网络",
    export: "导出",
    clear: "清除",
    confirmClear: "确认清除",
    logEmpty: "暂无活动。",
    profile: "配置",
    editorDetail: "Porta 会自动选择速度最快的安全传输方式。",
    profileName: "配置名称",
    profileNamePlaceholder: "家庭、工作、旅行…",
    gateway: "网关地址",
    accessToken: "访问令牌",
    accessTokenPlaceholder: "粘贴管理员提供的令牌",
    tokenHelpNew: "令牌将为当前 Windows 账户安全存储。",
    tokenHelpEdit: "留空可继续使用当前受保护的令牌。",
    delete: "删除",
    confirmDelete: "确认删除",
    cancel: "取消",
    save: "保存",
    dismiss: "关闭",
    editProfile: "编辑 {name}",
    selectProfile: "选择 {name}",
    connectProfile: "连接 {name}",
    disconnectProfile: "断开 {name}",
    addProfileTitle: "添加配置",
    editProfileTitle: "编辑配置",
    idle: "空闲",
    live: "实时",
    noAddress: "—",
    receivedSent: "{received} ↓ · {sent} ↑",
    savedTo: "日志已保存到 {path}",
    logCleared: "连接日志已清除。",
    disconnected: "已断开",
    ready: "就绪",
    connecting: "正在连接",
    connected: "已连接",
    reconnecting: "正在重新连接",
    disconnecting: "正在断开",
    configuringNetwork: "正在配置网络",
    recoveringNetwork: "正在恢复网络",
    restoringNetwork: "正在恢复网络",
    recoveryAvailable: "可以恢复网络",
    connectionError: "连接错误",
    recoveryFailed: "网络恢复失败",
    actionRequired: "需要处理",
    selectedProfile: "已选择",
    autoReconnect: "已启用自动重连",
    chooseProfile: "选择一个配置以建立连接。",
    addProfileDetail: "添加配置后即可连接。",
    profileReady: "{name} · {server}",
    establishingTunnel: "正在建立安全隧道…",
    configuringTunnel: "正在应用私有路由、DNS 和隧道 MTU…",
    connectedH3: "HTTP/3 MASQUE · 快速且稳定 · MTU {mtu}",
    connectedH2: "4 通道 HTTP/2 备用连接 · 已加密 · MTU {mtu}",
    connectedAuto: "加密隧道已启用 · MTU {mtu}",
    reconnectingDetail: "网络已变化，正在恢复安全隧道…",
    disconnectingDetail: "正在恢复正常网络访问…",
    recoveryDetail: "重新连接可恢复保护，也可以直接恢复正常网络。",
    recoveryActive: "正在恢复保留的防泄漏保护…",
    networkRestored: "正常网络访问已恢复。",
    recoveryPending: "网络仍在等待恢复。",
    invalidServer: "请输入有效的 HTTPS 网关地址。",
    httpsOriginRequired: "网关必须是没有路径、查询参数或凭据的 HTTPS 来源。",
    nameRequired: "请输入配置名称。",
    tokenRequired: "请输入访问令牌。",
  },
};

const statusKeys = {
  "Action required": "actionRequired",
  "Configuring network": "configuringNetwork",
  Connected: "connected",
  Connecting: "connecting",
  "Connection error": "connectionError",
  Disconnected: "disconnected",
  Disconnecting: "disconnecting",
  "Network recovery available": "recoveryAvailable",
  "Network recovery failed": "recoveryFailed",
  Ready: "ready",
  Reconnecting: "reconnecting",
  "Recovering network": "recoveringNetwork",
  "Restoring network": "restoringNetwork",
};

const profileStatusKeys = {
  "Auto reconnect enabled": "autoReconnect",
  "Selected profile": "selectedProfile",
  Ready: "ready",
};

const numberFormats = new Map();

const state = {
  snapshot: null,
  pendingSnapshot: null,
  snapshotFrame: 0,
  view: "home",
  language: initialLanguage(),
  editorProfile: null,
  deleteArmed: false,
  deleteTimer: 0,
  clearArmed: false,
  clearTimer: 0,
  messageTimer: 0,
  pendingAction: "",
  pendingProfileId: "",
  profileSignature: "",
  activitySignature: null,
  downloadHistory: Array(60).fill(0),
  uploadHistory: Array(60).fill(0),
  chartFrame: 0,
};

const $ = (id) => document.getElementById(id);

function initialLanguage() {
  try {
    const saved = localStorage.getItem("porta.language");
    if (saved === "en" || saved === "zh-CN") return saved;
  } catch (_) {
  }
  return navigator.languages?.some((value) => value.toLowerCase().startsWith("zh"))
    ? "zh-CN"
    : "en";
}

function t(key, values = {}) {
  const template = messages[state.language][key] ?? messages.en[key] ?? key;
  return Object.entries(values).reduce(
    (value, [name, replacement]) => value.split(`{${name}}`).join(String(replacement)),
    template,
  );
}

function setText(id, value) {
  const element = $(id);
  if (element && element.textContent !== value) element.textContent = value;
}

function applyStaticTranslations() {
  document.documentElement.lang = state.language;
  document.querySelectorAll("[data-i18n]").forEach((element) => {
    element.textContent = t(element.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((element) => {
    element.placeholder = t(element.dataset.i18nPlaceholder);
  });
  document.querySelectorAll("[data-i18n-aria-label]").forEach((element) => {
    element.setAttribute("aria-label", t(element.dataset.i18nAriaLabel));
  });
  document.querySelectorAll("[data-i18n-title]").forEach((element) => {
    element.title = t(element.dataset.i18nTitle);
  });
  const switchTo = state.language === "en" ? "switchToChinese" : "switchToEnglish";
  $("language-action").textContent = state.language === "en" ? "中" : "EN";
  $("language-action").setAttribute("aria-label", t(switchTo));
  $("language-action").title = t(switchTo);
}

function setLanguage(language, persist = true) {
  state.language = language === "zh-CN" ? "zh-CN" : "en";
  if (persist) {
    try {
      localStorage.setItem("porta.language", state.language);
    } catch (_) {
    }
  }
  applyStaticTranslations();
  resetClearAction();
  resetDeleteAction();
  updateEditorLabels();
  state.profileSignature = "";
  state.activitySignature = "";
  if (state.snapshot) applySnapshot(state.snapshot, false);
}

function translateKnownError(message) {
  const value = String(message || "");
  if (value === "profile name is required") return t("nameRequired");
  if (value === "token is required for a new profile") return t("tokenRequired");
  if (value.startsWith("invalid server URL:")) return t("invalidServer");
  if (value === "server URL must be an HTTPS origin") return t("httpsOriginRequired");
  return value;
}

async function call(name, ...args) {
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
  };
  const [command, parameters] = commands[name];
  try {
    const result = await invoke(command, parameters);
    hideError();
    return result;
  } catch (error) {
    const message = translateKnownError(error?.message || String(error));
    showError(message);
    throw new Error(message, { cause: error });
  }
}

function showError(message) {
  setText("error-text", message);
  $("error-banner").classList.remove("hidden");
}

function hideError() {
  $("error-banner").classList.add("hidden");
}

async function performAction(key, profileId, action) {
  if (state.pendingAction) return { ok: false };
  state.pendingAction = key;
  state.pendingProfileId = profileId || "";
  updatePendingState();
  try {
    return { ok: true, value: await action() };
  } catch (error) {
    return { ok: false, error };
  } finally {
    state.pendingAction = "";
    state.pendingProfileId = "";
    updatePendingState();
  }
}

function updatePendingState() {
  state.profileSignature = "";
  renderProfilesIfNeeded();
  const busy = Boolean(state.pendingAction);
  $("profile-form").querySelectorAll("input, button").forEach((element) => {
    element.disabled = busy;
  });
  $("language-action").disabled = busy;
  $("restore-action").disabled =
    busy || !state.snapshot?.recoveryAvailable || state.snapshot?.running ||
    state.snapshot?.restoring;
  const hasActivity = Boolean(state.snapshot?.activity?.length);
  $("export-action").disabled = busy || !hasActivity;
  $("clear-action").disabled = busy || !hasActivity;
}

function setView(view) {
  state.view = view === "activity" || view === "editor" ? view : "home";
  $("home-view").classList.toggle("hidden", state.view !== "home");
  $("activity-view").classList.toggle("hidden", state.view !== "activity");
  $("editor-view").classList.toggle("hidden", state.view !== "editor");
  $("activity-action").classList.toggle("hidden", state.view !== "home");
  $("home-action").classList.toggle("hidden", state.view === "home");
  $("add-action").classList.toggle(
    "hidden",
    state.view !== "home" || Boolean(state.snapshot?.startupBlocked),
  );
  window.scrollTo({ top: 0, behavior: "instant" });
}

function queueSnapshot(snapshot) {
  if (!snapshot) return;
  state.pendingSnapshot = snapshot;
  if (state.snapshotFrame) return;
  state.snapshotFrame = requestAnimationFrame(() => {
    state.snapshotFrame = 0;
    const next = state.pendingSnapshot;
    state.pendingSnapshot = null;
    applySnapshot(next, true);
  });
}

function applySnapshot(snapshot, recordTraffic) {
  if (!snapshot) return;
  const previous = state.snapshot;
  state.snapshot = snapshot;

  const status = t(statusKeys[snapshot.status] || "") || snapshot.status;
  setText("status-text", status);
  setText("status-detail", localizedDetail(snapshot));
  const tone = snapshot.tone === "connected"
    ? "connected"
    : snapshot.tone === "warning"
      ? "connecting"
      : snapshot.tone === "danger"
        ? "error"
        : "";
  $("status-icon").className = `status-icon ${tone}`.trim();
  $("traffic-card").classList.toggle("hidden", snapshot.startupBlocked);
  $("profiles-section").classList.toggle("hidden", snapshot.startupBlocked);
  $("add-action").classList.toggle(
    "hidden",
    snapshot.startupBlocked || state.view !== "home",
  );

  const totalsChanged = previous &&
    (previous.bytesDownloaded !== snapshot.bytesDownloaded ||
      previous.bytesUploaded !== snapshot.bytesUploaded);
  renderTraffic(snapshot, Boolean(recordTraffic && totalsChanged));
  renderProfilesIfNeeded();
  renderActivityIfNeeded();
  updateRecoveryAction();
  updateDuration();
}

function localizedDetail(snapshot) {
  if (snapshot.startupBlocked) return snapshot.detail;
  const selected = snapshot.profiles?.find((profile) => profile.id === snapshot.selectedProfileId);
  switch (snapshot.status) {
    case "Disconnected":
      return snapshot.profiles?.length ? t("chooseProfile") : t("addProfileDetail");
    case "Ready":
      return selected
        ? t("profileReady", { name: selected.name, server: cleanServer(selected.serverUrl) })
        : t("chooseProfile");
    case "Connecting":
      return t("establishingTunnel");
    case "Configuring network":
      return t("configuringTunnel");
    case "Connected":
      if (snapshot.transport === "h3") return t("connectedH3", { mtu: snapshot.mtu });
      if (snapshot.transport === "h2") return t("connectedH2", { mtu: snapshot.mtu });
      return t("connectedAuto", { mtu: snapshot.mtu });
    case "Reconnecting":
      return t("reconnectingDetail");
    case "Disconnecting":
    case "Restoring network":
      return t("disconnectingDetail");
    case "Network recovery available":
      return t("recoveryDetail");
    case "Recovering network":
      return t("recoveryActive");
    default:
      if (snapshot.detail === "Normal network access has been restored.") return t("networkRestored");
      if (snapshot.detail === "Network recovery remains pending.") return t("recoveryPending");
      return snapshot.detail;
  }
}

function applyTraffic(traffic) {
  if (!traffic || !state.snapshot) return;
  Object.assign(state.snapshot, traffic);
  renderTraffic(state.snapshot, true);
}

function renderTraffic(traffic, recordSample) {
  setText("traffic-state", traffic.running ? t("live") : t("idle"));
  setText("download-rate", formatRate(traffic.downloadRate));
  setText("upload-rate", formatRate(traffic.uploadRate));
  setText("session-address", traffic.address || t("noAddress"));
  setText(
    "session-total",
    t("receivedSent", {
      received: formatBytes(traffic.bytesDownloaded),
      sent: formatBytes(traffic.bytesUploaded),
    }),
  );

  const badge = $("transport-badge");
  const transport = traffic.transport ? traffic.transport.toUpperCase() : "";
  badge.textContent = transport;
  badge.classList.toggle("hidden", !transport || !traffic.connected);

  if (!state.snapshot || !traffic.connected) {
    if (!traffic.running) {
      state.downloadHistory.fill(0);
      state.uploadHistory.fill(0);
    }
  }
  if (recordSample) {
    state.downloadHistory.shift();
    state.uploadHistory.shift();
    state.downloadHistory.push(traffic.running ? Number(traffic.downloadRate) || 0 : 0);
    state.uploadHistory.push(traffic.running ? Number(traffic.uploadRate) || 0 : 0);
  }
  scheduleChart();
}

function profileSignature() {
  const snapshot = state.snapshot;
  return JSON.stringify({
    language: state.language,
    pendingAction: state.pendingAction,
    pendingProfileId: state.pendingProfileId,
    running: snapshot?.running,
    restoring: snapshot?.restoring,
    disconnecting: snapshot?.disconnecting,
    profiles: snapshot?.profiles,
  });
}

function renderProfilesIfNeeded() {
  if (!state.snapshot) return;
  const signature = profileSignature();
  if (signature === state.profileSignature) return;
  state.profileSignature = signature;
  renderProfiles();
}

function renderProfiles() {
  const list = $("profiles");
  const profiles = state.snapshot?.profiles || [];
  $("empty-state").classList.toggle("hidden", profiles.length !== 0);
  list.classList.toggle("hidden", profiles.length === 0);
  const fragment = document.createDocumentFragment();

  for (const profile of profiles) {
    const card = document.createElement("article");
    card.className = "profile-card";
    card.classList.toggle("selected", profile.selected);

    const avatar = document.createElement("span");
    avatar.className = "profile-avatar";
    avatar.textContent = firstLetter(profile.name);

    const copy = document.createElement("div");
    copy.className = "profile-copy";
    const name = document.createElement("strong");
    name.className = "profile-name";
    name.textContent = profile.name;
    const server = document.createElement("span");
    server.className = "profile-server";
    server.textContent = cleanServer(profile.serverUrl);
    const status = document.createElement("span");
    status.className = "profile-status";
    status.classList.toggle("active", profile.active);
    status.textContent = localizedProfileStatus(profile);
    copy.append(name, server, status);

    const edit = document.createElement("button");
    edit.type = "button";
    edit.className = "profile-edit";
    edit.disabled = Boolean(state.pendingAction) || state.snapshot.running || state.snapshot.restoring;
    edit.setAttribute("aria-label", t("editProfile", { name: profile.name }));
    edit.title = t("editProfile", { name: profile.name });
    edit.innerHTML =
      '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m4 15.8-.7 4.9 4.9-.7L19.6 8.6l-4.2-4.2L4 15.8Zm13.9-9-1.1 1.1-2.7-2.7 1.1-1.1a1.5 1.5 0 0 1 2.1 0l.6.6a1.5 1.5 0 0 1 0 2.1ZM6 16.7l7-7 2.7 2.7-7 7-3 .4.3-3.1Z"/></svg>';
    edit.addEventListener("click", (event) => {
      event.stopPropagation();
      openEditor(profile);
    });

    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "switch";
    toggle.classList.toggle("on", profile.active);
    toggle.classList.toggle("pending", state.pendingProfileId === profile.id);
    toggle.setAttribute("role", "switch");
    toggle.setAttribute(
      "aria-label",
      t(profile.active ? "disconnectProfile" : "connectProfile", { name: profile.name }),
    );
    toggle.setAttribute("aria-checked", profile.active ? "true" : "false");
    toggle.disabled = Boolean(state.pendingAction) || state.snapshot.restoring ||
      (state.snapshot.running && !profile.active);
    toggle.addEventListener("click", (event) => {
      event.stopPropagation();
      void toggleProfile(profile);
    });

    card.append(avatar, copy, edit, toggle);
    fragment.append(card);
  }
  list.replaceChildren(fragment);
}

function localizedProfileStatus(profile) {
  if (profile.active && state.snapshot?.disconnecting) return t("disconnecting");
  const key = statusKeys[profile.status] || profileStatusKeys[profile.status];
  return key ? t(key) : profile.status;
}

async function toggleProfile(profile) {
  await performAction(profile.active ? "disconnect" : "connect", profile.id, async () => {
    if (profile.active && state.snapshot.running) {
      await call("Disconnect");
      return;
    }
    if (!profile.selected) {
      applySnapshot(await call("SelectProfile", profile.id), false);
    }
    await call("Connect", profile.id);
  });
}

function openEditor(profile = null) {
  if (state.pendingAction) return;
  state.editorProfile = profile ? { ...profile } : null;
  resetDeleteAction();
  $("profile-name").value = profile?.name || "";
  $("profile-server").value = profile?.serverUrl || "https://";
  $("profile-token").value = "";
  $("delete-profile").classList.toggle("hidden", !profile);
  $("editor-error").classList.add("hidden");
  updateEditorLabels();
  setView("editor");
  requestAnimationFrame(() => $("profile-name").focus());
}

function updateEditorLabels() {
  setText("editor-title", t(state.editorProfile ? "editProfileTitle" : "addProfileTitle"));
  setText("token-help", t(state.editorProfile ? "tokenHelpEdit" : "tokenHelpNew"));
  if (!state.deleteArmed) setText("delete-profile", t("delete"));
}

function closeEditor() {
  setView("home");
  state.editorProfile = null;
  resetDeleteAction();
  $("editor-error").classList.add("hidden");
}

function showActivityMessage(message) {
  window.clearTimeout(state.messageTimer);
  setText("activity-message", message);
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
  setText("clear-action", t("clear"));
}

function resetDeleteAction() {
  window.clearTimeout(state.deleteTimer);
  state.deleteArmed = false;
  setText("delete-profile", t("delete"));
}

async function clearActivity() {
  if (!state.clearArmed) {
    state.clearArmed = true;
    setText("clear-action", t("confirmClear"));
    state.clearTimer = window.setTimeout(resetClearAction, 3500);
    return;
  }
  const outcome = await performAction("clear", "", () => call("ClearActivity"));
  resetClearAction();
  if (outcome.ok) showActivityMessage(t("logCleared"));
}

async function saveActivity() {
  const outcome = await performAction("export", "", () => call("SaveActivityLog"));
  if (outcome.ok && outcome.value) {
    showActivityMessage(t("savedTo", { path: outcome.value }));
  }
}

async function saveProfile(event) {
  event.preventDefault();
  const input = {
    id: state.editorProfile?.id || "",
    name: $("profile-name").value,
    serverUrl: $("profile-server").value,
    transport: state.editorProfile?.transport || "auto",
    token: $("profile-token").value,
  };
  const invalid = validateProfileInput(input);
  if (invalid) {
    setText("editor-error", invalid.message);
    $("editor-error").classList.remove("hidden");
    $(invalid.field).focus();
    return;
  }
  const outcome = await performAction("save", input.id, () => call("SaveProfile", input));
  if (!outcome.ok) {
    setText("editor-error", outcome.error?.message || String(outcome.error));
    $("editor-error").classList.remove("hidden");
    return;
  }
  queueSnapshot(outcome.value);
  closeEditor();
}

function validateProfileInput(input) {
  if (!input.name.trim()) return { field: "profile-name", message: t("nameRequired") };
  try {
    const url = new URL(input.serverUrl);
    if (
      url.protocol !== "https:" ||
      !url.hostname ||
      url.username ||
      url.password ||
      (url.pathname !== "" && url.pathname !== "/") ||
      url.search ||
      url.hash
    ) {
      return { field: "profile-server", message: t("httpsOriginRequired") };
    }
  } catch (_) {
    return { field: "profile-server", message: t("invalidServer") };
  }
  if (!state.editorProfile && !input.token.trim()) {
    return { field: "profile-token", message: t("tokenRequired") };
  }
  return null;
}

async function deleteProfile() {
  if (!state.editorProfile) return;
  if (!state.deleteArmed) {
    state.deleteArmed = true;
    setText("delete-profile", t("confirmDelete"));
    state.deleteTimer = window.setTimeout(resetDeleteAction, 3500);
    return;
  }
  const outcome = await performAction(
    "delete",
    state.editorProfile.id,
    () => call("DeleteProfile", state.editorProfile.id),
  );
  if (outcome.ok) {
    queueSnapshot(outcome.value);
    closeEditor();
  }
}

function renderActivityIfNeeded() {
  const activity = state.snapshot?.activity || [];
  const signature = activity.join("\u0000");
  if (signature === state.activitySignature) return;
  state.activitySignature = signature;
  setText("activity-log", activity.join("\n"));
  $("activity-empty").classList.toggle("hidden", activity.length !== 0);
  $("export-action").disabled = activity.length === 0 || Boolean(state.pendingAction);
  $("clear-action").disabled = activity.length === 0 || Boolean(state.pendingAction);
}

function updateRecoveryAction() {
  const available = Boolean(state.snapshot?.recoveryAvailable);
  $("restore-action").classList.toggle("hidden", !available);
  $("restore-action").disabled =
    Boolean(state.pendingAction) || !available || state.snapshot?.running ||
    state.snapshot?.restoring;
}

function formatBytes(value = 0) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = Number(value) || 0;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit++;
  }
  const digits = unit === 0 ? 0 : 1;
  const key = `${state.language}:${digits}`;
  if (!numberFormats.has(key)) {
    numberFormats.set(key, new Intl.NumberFormat(state.language, {
      maximumFractionDigits: digits,
      minimumFractionDigits: digits,
    }));
  }
  return `${numberFormats.get(key).format(size)} ${units[unit]}`;
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
    setText("session-duration", "00:00");
    return;
  }
  const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(connectedAt)) / 1000));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor(seconds / 60) % 60;
  const remainder = seconds % 60;
  const values = hours > 0 ? [hours, minutes, remainder] : [minutes, remainder];
  setText(
    "session-duration",
    values.map((value) => String(value).padStart(2, "0")).join(":"),
  );
}

function scheduleChart() {
  if (state.chartFrame) return;
  state.chartFrame = requestAnimationFrame(() => {
    state.chartFrame = 0;
    drawChart();
  });
}

function drawChart() {
  const canvas = $("traffic-chart");
  const rect = canvas.getBoundingClientRect();
  if (!rect.width || !rect.height) return;
  const scale = window.devicePixelRatio || 1;
  const pixelWidth = Math.max(1, Math.round(rect.width * scale));
  const pixelHeight = Math.max(1, Math.round(rect.height * scale));
  if (canvas.width !== pixelWidth || canvas.height !== pixelHeight) {
    canvas.width = pixelWidth;
    canvas.height = pixelHeight;
  }
  const context = canvas.getContext("2d");
  context.setTransform(scale, 0, 0, scale, 0, 0);
  const width = rect.width;
  const height = rect.height;
  context.clearRect(0, 0, width, height);
  context.strokeStyle = "rgba(152, 169, 189, 0.10)";
  context.lineWidth = 1;
  for (let row = 1; row < 4; row++) {
    const y = Math.round((height / 4) * row) + 0.5;
    context.beginPath();
    context.moveTo(0, y);
    context.lineTo(width, y);
    context.stroke();
  }
  const maximum = Math.max(1, ...state.downloadHistory, ...state.uploadHistory);
  drawSeries(
    context,
    state.downloadHistory,
    maximum,
    width,
    height,
    "#6ee7b7",
    "rgba(110, 231, 183, 0.11)",
  );
  drawSeries(
    context,
    state.uploadHistory,
    maximum,
    width,
    height,
    "#60a5fa",
    "rgba(96, 165, 250, 0.06)",
  );
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
  applyStaticTranslations();
  setView("home");
  await listen("porta:snapshot", (event) => queueSnapshot(event.payload));
  await listen("porta:traffic", (event) => applyTraffic(event.payload));
  await listen("porta:view", (event) => setView(event.payload));
  queueSnapshot(await call("Snapshot"));
}

$("activity-action").addEventListener("click", () => setView("activity"));
$("home-action").addEventListener("click", () => {
  if (state.view === "editor") closeEditor();
  else setView("home");
});
$("language-action").addEventListener("click", () => {
  setLanguage(state.language === "en" ? "zh-CN" : "en");
});
$("add-action").addEventListener("click", () => openEditor());
$("empty-add").addEventListener("click", () => openEditor());
$("editor-cancel").addEventListener("click", closeEditor);
$("profile-form").addEventListener("submit", saveProfile);
$("delete-profile").addEventListener("click", deleteProfile);
$("error-dismiss").addEventListener("click", hideError);
$("restore-action").addEventListener("click", async () => {
  await performAction("restore", "", () => call("RestoreNetwork"));
});
$("clear-action").addEventListener("click", clearActivity);
$("export-action").addEventListener("click", saveActivity);
window.addEventListener("resize", scheduleChart);
window.addEventListener("keydown", (event) => {
  if (event.key !== "Escape" || state.view === "home") return;
  if (state.view === "editor") closeEditor();
  else setView("home");
});
window.setInterval(updateDuration, 1000);

initialise().catch((error) => showError(translateKnownError(error?.message || String(error))));
