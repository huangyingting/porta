const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    elements.set(id, {
      value: '', textContent: '', hidden: true, open: false, listeners: {},
      classList: {add() {}, remove() {}, toggle() {}},
      addEventListener(name, callback) { this.listeners[name] = callback; },
      showModal() { this.open = true; },
      close() { this.open = false; this.listeners.close?.(); },
      removeAttribute(name) { delete this[name]; },
    });
  }
  return elements.get(id);
}
const pending = [];
const windowEvents = {};
const response = (body, status = 200) => ({status, ok: status === 200, json: async () => body});
const context = vm.createContext({
  document: {getElementById: element, querySelector: element, querySelectorAll: () => []},
  location: {protocol: 'https:', origin: 'https://vpn.example.test:8443'},
  AbortController, setInterval() {}, setTimeout() {}, clearTimeout() {},
  addEventListener(name, callback) { windowEvents[name] = callback; },
  fetch: async (path, options) => {
    if (path === '/api/clients') return response({clients: []});
    assert.equal(path, '/api/profile/qr');
    assert.equal(options.method, 'POST');
    assert.equal(options.headers['Content-Type'], 'application/json');
    return new Promise(resolve => pending.push({resolve, options, body: JSON.parse(options.body)}));
  },
});
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1], context);
const run = source => vm.runInContext(source, context);
const flush = () => new Promise(resolve => setImmediate(resolve));

(async () => {
  await flush();
  run('showToken("example-token-one", "Phone")');
  assert.deepEqual(pending[0].body, {name: 'Phone', server: context.location.origin, token: 'example-token-one'});
  pending[0].resolve(response({image: 'data:image/png;base64,first'}));
  await flush();
  assert.equal(element('profile-qr').src, 'data:image/png;base64,first');
  assert.equal(element('profile-qr').hidden, false);

  run('generateProfileQR()');
  element('qr-server').value = 'https://second.example.test:9443';
  run('clearProfileQR(); generateProfileQR()');
  assert.equal(pending[1].options.signal.aborted, true);
  assert.equal(pending[2].body.server, 'https://second.example.test:9443');
  pending[1].resolve(response({image: 'stale-image'}));
  await flush();
  assert.equal(element('profile-qr').src, undefined);
  pending[2].resolve(response({image: 'data:image/png;base64,second'}));
  await flush();
  assert.equal(element('profile-qr').src, 'data:image/png;base64,second');

  run('generateProfileQR()');
  pending[3].resolve(response({error: 'Enter a valid HTTPS server origin'}, 400));
  await flush();
  assert.equal(element('qr-status').textContent, 'Enter a valid HTTPS server origin');
  assert.equal(element('profile-qr').hidden, true);
  assert.equal(element('token-value').textContent, 'example-token-one');

  run('generateProfileQR()');
  element('token-dialog').close();
  assert.equal(element('token-value').textContent, '');
  assert.equal(element('qr-server').value, '');
  assert.equal(pending[4].options.signal.aborted, true);
  run('showToken("example-token-rotated", "Phone")');
  pending[5].resolve(response({image: 'data:image/png;base64,rotated'}));
  pending[4].resolve(response({image: 'stale-image'}));
  await flush();
  assert.equal(element('profile-qr').src, 'data:image/png;base64,rotated');
  assert.equal(element('token-value').textContent, 'example-token-rotated');
  windowEvents.pagehide();
  assert.equal(element('token-value').textContent, '');
  assert.equal(element('profile-qr').src, undefined);
  assert.equal(run('tokenProfileName'), '');

  context.location.protocol = 'http:';
  run('showToken("example-token-local", "Local administration")');
  assert.equal(pending.length, 6);
  assert.equal(element('qr-server').value, '');
  assert.match(element('qr-status').textContent, /public HTTPS/);
  context.location.protocol = 'https:';
  run('showToken("example-token-expired-session", "Phone")');
  pending[6].resolve(response({}));
  await flush();
  assert.match(element('qr-status').textContent, /Invalid QR response/);
  assert.equal(element('profile-qr').hidden, true);
  assert.equal(element('token-value').textContent, 'example-token-expired-session');
  windowEvents.pagehide();
  console.log('Admin QR lifecycle, origin selection, error handling, and stale response regressions passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
