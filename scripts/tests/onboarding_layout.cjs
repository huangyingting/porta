const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const {spawn} = require('node:child_process');
const {once} = require('node:events');

async function main() {
  const root = path.resolve(__dirname, '../..');
  const chromePath = process.env.CHROME_BIN || '/usr/bin/google-chrome';
  const profile = path.join(root, '.cache', 'onboarding-layout-' + process.pid);
  fs.mkdirSync(profile, {recursive: true});
  const assets = path.join(root, 'rust/porta-server/assets');
  const html = fs.readFileSync(path.join(assets, 'admin.html'), 'utf8');
  const font = fs.readFileSync(path.join(assets, 'MonaSans.woff2'));
  const server = http.createServer((request, response) => {
    if (request.url === '/api/clients') {
      response.setHeader('Content-Type', 'application/json');
      response.end('{"clients":[]}');
    } else if (request.url === '/assets/mona-sans.woff2') {
      response.setHeader('Content-Type', 'font/woff2');
      response.end(font);
    } else if (request.url === '/') {
      response.setHeader('Content-Type', 'text/html');
      response.end(html);
    } else {
      response.statusCode = 404;
      response.end();
    }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const chromeTimeoutMs = 30000;
  const chrome = spawn(chromePath, [
    '--headless', '--no-sandbox', '--disable-gpu', '--disable-background-networking',
    '--disable-component-update', '--disable-dev-shm-usage', '--no-first-run', '--no-default-browser-check',
    '--remote-debugging-pipe', '--user-data-dir=' + profile, 'about:blank',
  ], {env: {...process.env, TMPDIR: profile}, stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe']});
  const pending = new Map(), events = new Map();
  let sequence = 0, buffer = '', chromeStderr = '', chromeFailure;
  let chromeClosing = false, chromeClosed = false;
  const failure = message => {
    const details = chromeStderr.trim();
    return new Error(details ? `${message}\nChrome stderr:\n${details}` : message);
  };
  const rejectPending = error => {
    chromeFailure ||= error;
    for (const callback of pending.values()) callback.reject(chromeFailure);
    pending.clear();
  };
  const closed = new Promise(resolve => {
    chrome.once('close', (code, signal) => {
      chromeClosed = true;
      if (!chromeClosing) {
        rejectPending(failure(`Chrome exited before the layout checks completed (code=${code}, signal=${signal})`));
      }
      resolve();
    });
  });
  chrome.on('error', error => rejectPending(failure(`Chrome failed to start: ${error.message}`)));
  chrome.stderr.on('data', data => {
    chromeStderr = (chromeStderr + data.toString()).slice(-8192);
  });
  chrome.stderr.on('error', error => {
    if (!chromeClosing) rejectPending(failure(`Chrome stderr pipe failed: ${error.message}`));
  });
  for (const [name, stream] of [['command', chrome.stdio[3]], ['response', chrome.stdio[4]]]) {
    stream.on('error', error => {
      if (!chromeClosing) rejectPending(failure(`Chrome ${name} pipe failed: ${error.message}`));
    });
  }
  chrome.stdio[4].on('data', data => {
    buffer += data.toString();
    let end;
    while ((end = buffer.indexOf('\0')) !== -1) {
      let message;
      try {
        message = JSON.parse(buffer.slice(0, end));
      } catch (error) {
        rejectPending(failure(`Invalid Chrome protocol response: ${error.message}`));
        return;
      }
      buffer = buffer.slice(end + 1);
      if (message.id) {
        const callback = pending.get(message.id);
        pending.delete(message.id);
        if (message.error) callback?.reject(new Error(JSON.stringify(message.error)));
        else callback?.resolve(message.result);
      } else {
        events.get(message.sessionId + ':' + message.method)?.(message.params);
      }
    }
  });
  const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    if (chromeFailure) {
      reject(chromeFailure);
      return;
    }
    const id = ++sequence;
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(failure('Chrome protocol timeout: ' + method));
    }, chromeTimeoutMs);
    pending.set(id, {
      resolve(value) { clearTimeout(timer); resolve(value); },
      reject(error) { clearTimeout(timer); reject(error); },
    });
    try {
      chrome.stdio[3].write(JSON.stringify({id, method, params, sessionId}) + '\0');
    } catch (error) {
      pending.delete(id);
      clearTimeout(timer);
      reject(failure(`Chrome command pipe write failed: ${error.message}`));
    }
  });
  try {
    const {targetId} = await send('Target.createTarget', {url: 'about:blank'});
    const {sessionId} = await send('Target.attachToTarget', {targetId, flatten: true});
    const evaluate = async expression => {
      const result = await send('Runtime.evaluate', {expression, awaitPromise: true, returnByValue: true}, sessionId);
      assert.equal(result.exceptionDetails, undefined, JSON.stringify(result.exceptionDetails));
      return result.result.value;
    };
    await send('Page.enable', {}, sessionId);
    const loaded = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(failure('Browser page load timeout')), chromeTimeoutMs);
      events.set(sessionId + ':Page.loadEventFired', () => { clearTimeout(timer); resolve(); });
    });
    await send('Page.navigate', {url: 'http://127.0.0.1:' + server.address().port + '/'}, sessionId);
    await loaded;
    await evaluate('document.fonts.ready.then(()=>true)');
    await evaluate(`clients=[{id:'existing',name:'Product team',max_devices:5}];
      Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:()=>Promise.reject(new Error('Clipboard unavailable'))}});
      true`);
    for (const [width, height] of [[390, 844], [320, 568], [844, 390]]) {
      await send('Emulation.setDeviceMetricsOverride', {width, height, deviceScaleFactor: 1, mobile: true}, sessionId);
      const states = [
        ['create', "openCreate()"],
        ['edit', "openEdit('existing')"],
        ['access-ready', "showToken('private-token','Product team');document.getElementById('access-status').textContent='Ready to share. Save now: the token cannot be shown again.'"],
        ['access-error', "showToken('private-token','Product team');document.getElementById('access-status').textContent='Access link unavailable. Copy the token now; it cannot be shown again.';document.getElementById('retry-access').hidden=false"],
        ['access-fallback', "showToken('private-token','Product team');document.getElementById('retry-access').hidden=false;await copyToken()"],
      ];
      for (const [name, setup] of states) {
        const result = await evaluate(`(async()=>{
          closeTokenDialog();closeDialog();${setup};
          const dialog=document.querySelector('dialog[open]'),bounds=dialog.getBoundingClientRect();
          return {width:innerWidth,height:innerHeight,top:bounds.top,bottom:bounds.bottom,
            clientHeight:dialog.clientHeight,scrollHeight:dialog.scrollHeight,
            clientWidth:dialog.clientWidth,scrollWidth:dialog.scrollWidth,
            locked:document.body.classList.contains('modal-open'),focus:document.activeElement.tagName};
        })()`);
        const label = `${width}x${height} ${name}: ${JSON.stringify(result)}`;
        assert.equal(result.width, width, label);
        assert.equal(result.height, height, label);
        assert.equal(result.locked, true, label);
        assert.ok(result.top >= 0 && result.bottom <= height, label);
        assert.ok(result.scrollHeight <= result.clientHeight, label);
        assert.ok(result.scrollWidth <= result.clientWidth, label);
        if (name !== 'access-fallback') assert.equal(result.focus, 'BUTTON', label);
        console.log(`${width}x${height} ${name}: ${result.clientHeight}px, no overflow`);
      }
    }
    await evaluate('closeTokenDialog();closeDialog();true');
    assert.equal(await evaluate("document.body.classList.contains('modal-open')"), false);
  } finally {
    chromeClosing = true;
    if (!chromeClosed) chrome.kill();
    await closed;
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(profile, {recursive: true, force: true});
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
