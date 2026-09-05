const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const elements = new Map(), closeEvents = [], windowEvents = {}, copied = [];
function element(id) {
  if (!elements.has(id)) {
    const classes = new Set();
    elements.set(id, {
      value: '', textContent: '', hidden: true, open: false, listeners: {}, style: {top: ''},
      classList: {add(name) { classes.add(name); }, remove(name) { classes.delete(name); }, contains(name) { return classes.has(name); }, toggle() {}},
      addEventListener(name, callback) { this.listeners[name] = callback; },
      showModal() { this.open = true; },
      close() { if (this.open) { this.open = false; closeEvents.push(() => this.listeners.close?.()); } },
      removeAttribute(name) { delete this[name]; },
      setAttribute(name, value) { this[name] = value; },
      focus() { context.document.activeElement = this; },
      select() { this.selected = true; },
    });
  }
  return elements.get(id);
}
const pending = [];
const response = (body, status = 200) => ({status, ok: status === 200, json: async () => body});
const context = vm.createContext({
  document: {getElementById: element, querySelector: element, querySelectorAll: () => [], body: element('body')},
  location: {protocol: 'https:', origin: 'https://vpn.example.test:8443'},
  window: {scrollY: 173, scrollTo(x, y) { this.scrollY = y; }},
  navigator: {clipboard: {async writeText(value) { copied.push(value); }}},
  URL, URLSearchParams, AbortController, setInterval() {}, setTimeout() {}, clearTimeout() {},
  addEventListener(name, callback) { windowEvents[name] = callback; },
  fetch: async (route, options) => {
    if (route === '/api/clients') return response({clients: []});
    assert.equal(route, '/api/client-access');
    assert.equal(options.method, 'POST');
    assert.equal(options.cache, 'no-store');
    assert.equal(options.headers['Content-Type'], 'application/json');
    return new Promise(resolve => pending.push({resolve, options, body: JSON.parse(options.body)}));
  },
});
const source = fs.readFileSync(process.argv[2], 'utf8');
const tokenHTML = source.match(/<dialog id="token-dialog"[\s\S]*?<\/dialog>/)[0];
assert.doesNotMatch(tokenHTML, /<img|qr-server|profile-qr/);
assert.match(tokenHTML, /download="porta-download-access.png"/);
assert.match(tokenHTML, /id="access-done"[^>]*autofocus/);
vm.runInContext(source.match(/<script>([\s\S]*?)<\/script>/)[1], context);
const run = code => vm.runInContext(code, context);
const flush = () => new Promise(resolve => setImmediate(resolve));
const dispatchClose = () => { while (closeEvents.length) closeEvents.shift()(); };
const ready = ticket => ({
  url: context.location.origin + '/join#invite=' + ticket,
  image: 'data:image/png;base64,aW1hZ2U=',
  expires_at: new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString(),
});
const assertCleared = () => {
  assert.equal(run('rawClientToken'), '');
  assert.equal(element('access-link').value, '');
  assert.equal(element('save-access-qr').href, undefined);
  assert.equal(element('save-access-qr')['aria-disabled'], 'true');
  assert.equal(element('token-fallback').value, '');
  assert.equal(element('token-fallback-field').hidden, true);
  assert.equal(element('copy-access').disabled, true);
};

(async () => {
  await flush();
  run('openCreate()');
  assert.equal(element('client-dialog').open, true);
  assert.equal(element('body').classList.contains('modal-open'), true);
  assert.equal(context.document.activeElement, element('save-client'));
  run('showToken("example-token-one", "Phone")');
  assert.equal(element('client-dialog').open, false);
  assert.equal(element('token-dialog').open, true);
  dispatchClose();
  assert.equal(element('body').classList.contains('modal-open'), true, 'closing the create modal must not unlock an open token modal');
  assert.equal(context.document.activeElement, element('access-done'));
  assert.deepEqual(pending[0].body, {origin: context.location.origin, token: 'example-token-one'});
  pending[0].resolve(response(ready('first')));
  await flush();
  assert.equal(element('access-link').value, ready('first').url);
  assert.equal(element('save-access-qr').href, ready('first').image);
  assert.equal(element('save-access-qr').tabIndex, 0);
  assert.equal(element('copy-access').disabled, false);
  await run('copyAccessLink(); copyToken()');
  assert.deepEqual(copied, [ready('first').url, 'example-token-one']);

  run('generateClientAccess(); generateClientAccess()');
  assert.equal(pending[1].options.signal.aborted, true);
  pending[1].resolve(response(ready('stale')));
  await flush();
  assert.equal(element('access-link').value, '');
  pending[2].resolve(response(ready('second')));
  await flush();
  assert.equal(element('access-link').value, ready('second').url);

  run('generateClientAccess()');
  pending[3].resolve(response({error: 'Secret data must not be echoed into the UI'}, 500));
  await flush();
  assert.match(element('access-status').textContent, /Copy the token now/);
  assert.doesNotMatch(element('access-status').textContent, /Secret data/);
  assert.equal(element('retry-access').hidden, false);
  assert.equal(element('save-access-qr').href, undefined);
  assert.equal(run('rawClientToken'), 'example-token-one');
  context.navigator.clipboard.writeText = async () => { throw new Error('Unavailable'); };
  await run('copyToken()');
  assert.equal(element('token-fallback').value, 'example-token-one');
  assert.equal(element('token-fallback-field').hidden, false);
  assert.equal(element('token-fallback').selected, true);

  run('generateClientAccess()');
  run('closeTokenDialog()');
  assert.equal(pending[4].options.signal.aborted, true);
  assertCleared();
  assert.equal(element('body').classList.contains('modal-open'), false);
  assert.equal(context.window.scrollY, 173);
  run('showToken("example-token-rotated", "Phone")');
  dispatchClose();
  assert.equal(run('rawClientToken'), 'example-token-rotated', 'delayed close event must not erase a reopened dialog');
  pending[5].resolve(response(ready('rotated')));
  pending[4].resolve(response(ready('stale-closed')));
  await flush();
  assert.equal(element('access-link').value, ready('rotated').url);
  assert.equal(run('rawClientToken'), 'example-token-rotated');

  const invalid = [
    {},
    {...ready('x'), url: 'https://other.example.test/join#invite=x'},
    {...ready('x'), url: 'http://vpn.example.test:8443/join#invite=x'},
    {...ready('x'), url: 'https://user:pass@vpn.example.test:8443/join#invite=x'},
    {...ready('x'), url: context.location.origin + '/access#invite=x'},
    {...ready('x'), url: context.location.origin + '/join?token=secret#invite=x'},
    {...ready('x'), url: context.location.origin + '/join#invite='},
    {...ready('x'), url: context.location.origin + '/join#invite=%20'},
    {...ready('x'), url: context.location.origin + '/join#other=x'},
    {...ready('x'), url: context.location.origin + '/join#invite=x&invite=y'},
    {...ready('x'), url: context.location.origin + '/join#invite=x&extra=y'},
    {...ready('x'), url: context.location.origin + '/join#invite=' + 'a'.repeat(4097)},
    {...ready('x'), image: 'https://other.example.test/qr.png'},
    {...ready('x'), image: 'data:image/svg+xml;base64,aW1hZ2U='},
    {...ready('x'), image: 'data:image/png;base64,'},
    {...ready('x'), expires_at: 'not a date'},
  ];
  for (const body of invalid) {
    run('generateClientAccess()');
    pending.at(-1).resolve(response(body));
    await flush();
    assert.equal(element('access-link').value, '');
    assert.equal(element('save-access-qr').href, undefined);
    assert.match(element('access-status').textContent, /Access link unavailable/);
    assert.equal(run('rawClientToken'), 'example-token-rotated');
  }
  run('generateClientAccess()');
  const beforeEdit = pending.at(-1);
  run('clients=[{id:"existing",name:"Existing",max_devices:5}]; openEdit("existing")');
  assert.equal(beforeEdit.options.signal.aborted, true);
  assertCleared();
  dispatchClose();
  assert.equal(element('body').classList.contains('modal-open'), true);
  beforeEdit.resolve(response(ready('stale-edit')));
  await flush();
  assertCleared();

  run('showToken("example-token-pagehide", "Phone")');
  const beforeHide = pending.at(-1);
  windowEvents.pagehide();
  assert.equal(beforeHide.options.signal.aborted, true);
  assertCleared();
  dispatchClose();
  assert.equal(element('body').classList.contains('modal-open'), false);
  beforeHide.resolve(response(ready('stale-pagehide')));
  await flush();
  assertCleared();

  const requests = pending.length;
  context.location.protocol = 'http:';
  run('showToken("example-token-local", "Local administration")');
  assert.equal(pending.length, requests);
  assert.match(element('access-status').textContent, /HTTPS/);
  assert.equal(run('rawClientToken'), 'example-token-local');
  windowEvents.pagehide();
  context.location.protocol = 'https:';
  run('showToken("clipboard-race-token", "Phone")');
  let rejectCopy;
  context.navigator.clipboard.writeText = () => new Promise((resolve, reject) => { rejectCopy = reject; });
  run('copyToken(); closeTokenDialog()');
  rejectCopy(new Error('Unavailable'));
  await flush();
  assertCleared();
  await require('./portal_onboarding_ui.cjs')(path.dirname(path.resolve(process.argv[2])));
  console.log('Admin access QR validation, token fallback, modal lifecycle, stale requests and clipboard races passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
