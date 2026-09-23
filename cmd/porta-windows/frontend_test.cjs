const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

const directory = path.join(__dirname, "frontend");
const html = fs.readFileSync(path.join(directory, "index.html"), "utf8");
const app = fs.readFileSync(path.join(directory, "app.js"), "utf8")
  .replace(/^import .*;$/gm, "")
  .replace(/initialise\(\)\.catch\([^\n]+\);/, "");
const i18n = fs.readFileSync(path.join(directory, "i18n.js"), "utf8").replace(/^export /gm, "");

function harness(language = "en") {
  class Element {
    constructor() {
      this.textContent = "";
      this.value = "";
      this.disabled = false;
      this.dataset = {};
      this.children = [];
      this.attributes = {};
      this.handlers = {};
      const classes = new Set();
      this.classList = {
        add: (...names) => names.forEach((name) => classes.add(name)),
        remove: (...names) => names.forEach((name) => classes.delete(name)),
        contains: (name) => classes.has(name),
        toggle: (name, value) => (value ?? !classes.has(name)) ? classes.add(name) : classes.delete(name),
      };
    }
    setAttribute(key, value) { this.attributes[key] = value; }
    getAttribute(key) { return this.attributes[key]; }
    addEventListener(name, handler) { this.handlers[name] = handler; }
    append(...items) { this.children.push(...items); }
    replaceChildren(...items) { this.children = items; this.replaced = (this.replaced || 0) + 1; }
    querySelectorAll() { return []; }
    focus() { this.focused = true; }
    getBoundingClientRect() { return { width: 0, height: 0 }; }
  }
  const elements = Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map((match) => [match[1], new Element()]));
  const translated = [...html.matchAll(/<[^>]+\bdata-i18n>([^<]*)/g)].map((match) => {
    const element = new Element();
    element.textContent = match[1].trim();
    return element;
  });
  const storage = new Map();
  const calls = [];
  const timers = new Map();
  let timer = 0;
  const context = vm.createContext({
    console, URL, Intl, Date,
    navigator: { languages: [language] },
    localStorage: { getItem: (key) => storage.get(key), setItem: (key, value) => storage.set(key, value) },
    Call: { ByName: async (...args) => { calls.push(args); return null; } },
    Events: { On() {} },
    document: {
      documentElement: {}, getElementById: (id) => {
        assert.ok(elements[id], `missing element ${id}`);
        return elements[id];
      },
      createElement: () => new Element(),
      querySelectorAll: (selector) => selector === "[data-i18n]" ? translated : [],
    },
    requestAnimationFrame: (callback) => { callback(); return 1; },
    window: {
      clearTimeout: (id) => timers.delete(id),
      setTimeout: (callback) => { timers.set(++timer, callback); return timer; },
      setInterval() {}, addEventListener() {}, devicePixelRatio: 1,
    },
  });
  vm.runInContext(i18n + "\n" + app + "\nglobalThis.api = { state, setLanguage, applySnapshot, applyTraffic, validateProfileInput, openEditor, closeEditor, saveProfile, performAction, deleteProfile, renderProfiles, translate };", context);
  const snapshot = {
    version: "test", profiles: [{ id: "one", name: "Home", serverUrl: "https://gateway",
      transport: "auto", selected: true, active: false, status: "Selected profile" }],
    selectedProfileId: "one", status: "Ready", detail: "Home", running: false, connected: false,
    restoring: false, recoveryAvailable: false, bytesDownloaded: 0, bytesUploaded: 0, activity: [],
  };
  context.api.applySnapshot(snapshot);
  return { api: context.api, context, elements, calls, timers, storage, snapshot, translated };
}

test("English/Chinese localization persists and covers the static screens", () => {
  const h = harness("zh-Hans");
  assert.equal(h.api.state.language, "zh-CN");
  h.api.setLanguage("zh-CN");
  assert.equal(h.storage.get("porta.language"), "zh-CN");
  assert.equal(h.elements["status-title"].textContent, "就绪");
  for (const element of h.translated) {
    assert.notEqual(element.textContent, element.dataset.i18n, `missing translation: ${element.dataset.i18n}`);
  }
  h.api.setLanguage("en");
  assert.equal(h.elements["status-title"].textContent, "Ready");
  assert.equal(h.elements["language-action"].textContent, "中");
});

test("editor rejects non-origins and validates before crossing the Wails binding", async () => {
  const h = harness();
  const input = { id: "", name: "Home", serverUrl: "https://gateway", token: "secret" };
  for (const serverUrl of ["http://gateway", "https://user:pass@gateway", "https://gateway/path", "https://gateway?", "https://gateway#", "invalid"]) {
    assert.equal(h.api.validateProfileInput({ ...input, serverUrl }).field, "profile-server");
  }
  assert.equal(h.api.validateProfileInput({ ...input, name: "" }).field, "profile-name");
  assert.equal(h.api.validateProfileInput({ ...input, token: "" }).field, "profile-token");
  assert.equal(h.api.validateProfileInput({ ...input, id: "one", token: "" }), null);
  assert.equal(h.api.validateProfileInput({ ...input, serverUrl: "https://[2001:db8::1]:8443/" }), null);
  h.api.openEditor();
  await h.api.saveProfile({ preventDefault() {} });
  assert.equal(h.calls.length, 0);
  assert.equal(h.elements["editor-error"].classList.contains("hidden"), false);
});

test("traffic updates include equal and idle samples without rebuilding profiles", () => {
  const h = harness();
  h.api.applySnapshot({ ...h.snapshot, connected: true, running: true, transport: "h3", mtu: 1280 });
  const renders = h.elements.profiles.replaced;
  for (const rate of [50, 50, 0]) {
    h.api.applyTraffic({ downloadRate: rate, uploadRate: rate, bytesDownloaded: 100 });
  }
  assert.deepEqual(Array.from(h.api.state.downloadHistory.slice(-3)), [50, 50, 0]);
  assert.equal(h.elements.profiles.replaced, renders);
  assert.equal(h.elements["transport-badge"].textContent, "H3");
  assert.equal(h.elements["transport-badge"].classList.contains("hidden"), false);
  h.api.applySnapshot(h.snapshot);
  assert.ok(h.api.state.downloadHistory.every((value) => value === 0));
});

test("pending actions suppress duplicate submissions and keep editor fields", async () => {
  const h = harness();
  h.api.openEditor(h.snapshot.profiles[0]);
  h.elements["profile-token"].value = "new token";
  let release;
  let runs = 0;
  const first = h.api.performAction("save", () => new Promise((resolve) => { runs++; release = resolve; }));
  await h.api.performAction("save", () => { runs++; });
  h.api.closeEditor();
  assert.equal(h.api.state.view, "editor");
  assert.equal(runs, 1);
  release(true);
  await first;
  h.api.closeEditor();
  assert.equal(h.api.state.view, "home");
  assert.equal(h.elements["profile-token"].value, "");
});

test("startup recovery error blocks connection controls and profile editing", () => {
  const h = harness();
  h.api.applySnapshot({ ...h.snapshot, startupBlocked: true, status: "Action required", detail: "legacy recovery state" });
  assert.equal(h.elements["profiles-section"].classList.contains("hidden"), true);
  assert.equal(h.elements["traffic-card"].classList.contains("hidden"), true);
  assert.equal(h.elements["primary-connect"].disabled, true);
  assert.equal(h.elements["status-detail"].textContent, "legacy recovery state");
  h.api.openEditor();
  assert.notEqual(h.api.state.view, "editor");
});

test("profile transport stays automatic by default and preserves explicit choices", () => {
  const h = harness();
  h.api.openEditor();
  assert.equal(h.elements["profile-transport"].value, "auto");
  h.api.openEditor({ ...h.snapshot.profiles[0], transport: "h2" });
  assert.equal(h.elements["profile-transport"].value, "h2");
});

test("delete confirmation expires, and a failed binding keeps the editor open", async () => {
  const h = harness();
  h.api.openEditor(h.snapshot.profiles[0]);
  await h.api.deleteProfile();
  assert.equal(h.api.state.deleteArmed, true);
  h.timers.get(h.api.state.deleteTimer)();
  assert.equal(h.api.state.deleteArmed, false);
  await h.api.performAction("save", async () => { throw new Error("failed to save"); });
  assert.equal(h.api.state.view, "editor");
  assert.equal(h.elements["editor-error"].textContent, "failed to save");
  assert.equal(h.api.state.pendingAction, "");
});
