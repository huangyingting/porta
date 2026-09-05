const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

module.exports = async function testOnboarding(directory) {
  const script = (file, name) => fs.readFileSync(path.join(directory, file), 'utf8')
    .match(new RegExp('const ' + name + ' = `([\\s\\S]*?)`'))[1];
  const joinScript = script('portal_join_page.go', 'portalJoinScript');
  function join(hash, state = 'auto', historyFailure = false) {
    const events = {}, order = [], forms = [];
    const location = {hash, search: '?untrusted=query', reload() { order.push('reload'); }};
    const nodes = new Map([
      ['portal-join', {dataset: {joinState: state}}],
      ['join-heading', {textContent: 'Server heading'}],
      ['join-detail', {textContent: 'Server message'}],
    ]);
    const context = vm.createContext({
      URLSearchParams,
      location,
      history: {replaceState(data, title, url) { order.push('clear'); assert.equal(url, '/join'); if (historyFailure) throw new Error('blocked'); location.hash = ''; location.search = ''; }},
      addEventListener(name, callback) { events[name] = callback; },
      document: {
        getElementById(id) { return nodes.get(id); },
        body: {appendChild(form) { forms.push(form); }},
        createElement(tag) {
          return {
            tag, children: [],
            appendChild(child) { this.children.push(child); },
            submit() { order.push('submit'); },
            remove() { this.removed = true; },
            removeAttribute(name) { if (name === 'value') this.defaultValue = ''; else delete this[name]; },
          };
        },
      },
    });
    vm.runInContext(joinScript, context);
    return {nodes, forms, events, order, location};
  }
  const valid = join('#invite=opaque%2Bticket%2Fvalue%3D');
  assert.deepEqual(valid.order, ['clear', 'submit']);
  assert.equal(valid.forms.length, 1);
  assert.equal(valid.forms[0].method, 'POST');
  assert.equal(valid.forms[0].action, '/join/redeem');
  assert.equal(valid.forms[0].hidden, true);
  assert.equal(valid.forms[0].children[0].name, 'ticket');
  assert.equal(valid.forms[0].children[0].value, 'opaque+ticket/value=');
  valid.events.pagehide();
  assert.equal(valid.forms[0].children[0].value, '');
  assert.equal(valid.forms[0].removed, true);
  valid.events.pageshow({persisted: true});
  assert.equal(valid.nodes.get('portal-join').dataset.joinState, 'error');
  assert.equal(join('#invite=' + 'a'.repeat(4096)).forms.length, 1);
  for (const hash of ['', '#', '#invite=', '#invite=%20%20', '#ticket=secret', '#invite=x&invite=y', '#invite=x&unknown=y', '#invite=' + 'a'.repeat(4097)]) {
    const result = join(hash);
    assert.deepEqual(result.order, ['clear']);
    assert.equal(result.forms.length, 0);
    assert.equal(result.nodes.get('portal-join').dataset.joinState, 'error');
    assert.match(result.nodes.get('join-detail').textContent, /invalid or expired/);
    assert.doesNotMatch(result.nodes.get('join-detail').textContent, /secret/);
  }
  const serverError = join('#invite=must-not-submit', 'error');
  assert.equal(serverError.forms.length, 0);
  assert.deepEqual(serverError.order, ['clear']);
  assert.equal(serverError.nodes.get('join-detail').textContent, 'Server message');
  serverError.events.hashchange();
  assert.deepEqual(serverError.order, ['clear']);
  serverError.location.hash = '#invite=new-invitation';
  serverError.events.hashchange();
  assert.deepEqual(serverError.order, ['clear', 'reload']);
  assert.equal(serverError.forms.length, 0);
  assert.equal(join('#invite=valid', 'auto', true).forms.length, 0);

  const events = {}, nodes = new Map(), copied = [];
  function node(id) {
    if (!nodes.has(id)) nodes.set(id, {
      value: '', type: 'text', listeners: {},
      addEventListener(name, callback) { this.listeners[name] = callback; },
      setAttribute(name, value) { this[name] = value; },
      removeAttribute(name) { if (name === 'value') this.defaultValue = ''; else delete this[name]; },
      select() { this.selected = true; },
      querySelectorAll() { return [node('setup-copy-server'), node('setup-copy-token'), node('setup-reveal-token'), node('setup-copy-uri')]; },
    });
    return nodes.get(id);
  }
  let reloads = 0;
  const context = vm.createContext({
    document: {getElementById: node},
    navigator: {clipboard: {async writeText(value) { copied.push(value); }}},
    location: {reload() { reloads++; }},
    addEventListener(name, callback) { events[name] = callback; },
  });
  node('setup-server').value = 'https://vpn.example.test';
  node('setup-token').value = 'private-token';
  node('setup-token').type = 'password';
  node('setup-uri').value = 'porta://profile?v=1&server=https%3A%2F%2Fvpn.example.test&token=private-token';
  node('setup-uri').type = 'hidden';
  node('setup-qr').src = 'data:image/png;base64,aW1hZ2U=';
  vm.runInContext(script('client_setup_page.go', 'portalClientScript'), context);
  node('setup-reveal-token').listeners.click();
  assert.equal(node('setup-token').type, 'text');
  assert.equal(node('setup-reveal-token')['aria-pressed'], 'true');
  node('setup-reveal-token').listeners.click();
  assert.equal(node('setup-token').type, 'password');
  await node('setup-copy-token').listeners.click();
  await node('setup-copy-server').listeners.click();
  await node('setup-copy-uri').listeners.click();
  assert.deepEqual(copied, ['private-token', 'https://vpn.example.test', node('setup-uri').value]);
  context.navigator.clipboard.writeText = async () => { throw new Error('Denied'); };
  await node('setup-copy-uri').listeners.click();
  assert.match(node('setup-status').textContent, /Clipboard unavailable/);
  assert.equal(node('setup-uri').type, 'hidden');
  assert.equal(node('setup-uri').selected, undefined);
  await node('setup-copy-token').listeners.click();
  assert.equal(node('setup-token').type, 'text');
  assert.equal(node('setup-token').selected, true);
  let rejectCopy;
  context.navigator.clipboard.writeText = () => new Promise((resolve, reject) => { rejectCopy = reject; });
  const copying = node('setup-copy-uri').listeners.click();
  events.pagehide();
  rejectCopy(new Error('Denied after navigation'));
  await copying;
  assert.equal(node('setup-token').value, '');
  assert.equal(node('setup-token').defaultValue, '');
  assert.equal(node('setup-token').type, 'password');
  assert.equal(node('setup-uri').value, '');
  assert.equal(node('setup-uri').defaultValue, '');
  assert.equal(node('setup-copy-uri').disabled, true);
  assert.equal(node('setup-qr').src, undefined);
  assert.equal(node('setup-qr').hidden, true);
  assert.equal(node('setup-copy-token').disabled, true);
  assert.equal(node('setup-status').textContent, '');
  events.pageshow({persisted: false});
  assert.equal(reloads, 0);
  events.pageshow({persisted: true});
  assert.equal(reloads, 1);
  console.log('Join fragment redemption and client profile copy, reveal, cleanup and bfcache regressions passed.');
};

if (require.main === module) {
  module.exports(process.argv[2] || path.resolve(__dirname, '../../cmd/porta-server'))
    .catch(error => { console.error(error); process.exitCode = 1; });
}
