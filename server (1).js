#!/usr/bin/env node
/*
 * Speed test helper.
 * Serves speedtest.html and runs proxy tests: the browser sends a proxy address,
 * this program connects through that proxy (HTTP CONNECT or SOCKS5) and measures
 * ping, download and upload against Cloudflare's speed endpoints.
 *
 * Usage:  node server.js      then open http://localhost:3000
 * Needs Node 16 or newer. No packages to install.
 */
'use strict';
const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const BIND = '127.0.0.1';                       // local only: never expose this to a network
const [TH, TP_RAW] = (process.env.SPEEDTEST_TARGET || 'speed.cloudflare.com:443').split(':');
const TP = Number(TP_RAW) || 443;
const UA = 'Mozilla/5.0 (compatible; speedtest-proxy-helper)';
const STEP_TIMEOUT = 10000;
const DOWN_MS = 10000, UP_MS = 8000, WARM_MS = 1500;

/* ---------- Proxy address parsing ---------- */
function parseProxy(input, type) {
  let s = String(input || '').trim();
  let scheme = null;
  const m = s.match(/^([a-z0-9]+):\/\//i);
  if (m) { scheme = m[1].toLowerCase(); s = s.slice(m[0].length); }
  s = s.replace(/\/.*$/, '');
  let auth = null;
  const at = s.lastIndexOf('@');
  if (at >= 0) { auth = s.slice(0, at); s = s.slice(at + 1); }
  const i = s.lastIndexOf(':');
  if (i < 1) throw new Error('Use the format ip:port, for example 203.0.113.5:8080');
  const host = s.slice(0, i).replace(/^\[|\]$/g, '');
  const port = Number(s.slice(i + 1));
  if (!(port > 0 && port < 65536)) throw new Error('The proxy port must be a number from 1 to 65535');
  let user = null, pass = '';
  if (auth) {
    const j = auth.indexOf(':');
    user = decodeURIComponent(j < 0 ? auth : auth.slice(0, j));
    pass = j < 0 ? '' : decodeURIComponent(auth.slice(j + 1));
  }
  let kind = type || 'auto';
  if (scheme) kind = scheme.startsWith('socks') ? 'socks5' : 'http';
  if (!['auto', 'http', 'socks5'].includes(kind)) kind = 'auto';
  return { host, port, user, pass, kind };
}

/* ---------- Low-level tunnel code ---------- */
function friendly(e) {
  const c = e && e.code;
  if (c === 'ECONNREFUSED') return new Error('The proxy refused the connection (wrong port, or it is not running)');
  if (c === 'ENOTFOUND' || c === 'EAI_AGAIN') return new Error('The proxy host could not be found');
  if (c === 'ECONNRESET') return new Error('The proxy closed the connection unexpectedly');
  if (c === 'EHOSTUNREACH' || c === 'ENETUNREACH') return new Error('The proxy host is unreachable from this computer');
  return e instanceof Error ? e : new Error(String(e));
}

function tcpConnect(host, port, timeout) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host, port });
    const t = setTimeout(() => { s.destroy(); reject(new Error('Timed out connecting to the proxy')); }, timeout);
    s.once('connect', () => { clearTimeout(t); s.setNoDelay(true); resolve(s); });
    s.once('error', e => { clearTimeout(t); reject(friendly(e)); });
  });
}

function reader(sock) {
  let buf = Buffer.alloc(0), waiter = null, err = null, ended = false;
  const wake = () => { if (waiter) { const w = waiter; waiter = null; w(); } };
  const onData = d => { buf = Buffer.concat([buf, d]); wake(); };
  const onError = e => { err = e; wake(); };
  const onClose = () => { ended = true; wake(); };
  sock.on('data', onData); sock.on('error', onError); sock.on('close', onClose);
  const wait = ms => new Promise((resolve, reject) => {
    const t = setTimeout(() => { waiter = null; reject(new Error('The proxy did not answer in time')); }, ms);
    waiter = () => { clearTimeout(t); resolve(); };
  });
  const check = () => {
    if (err) throw friendly(err);
    if (ended) throw new Error('The proxy closed the connection');
  };
  return {
    async take(n, ms) {
      while (buf.length < n) { check(); await wait(ms); }
      const out = buf.subarray(0, n); buf = buf.subarray(n); return out;
    },
    async head(ms) {
      for (;;) {
        const i = buf.indexOf('\r\n\r\n');
        if (i >= 0) { const out = buf.subarray(0, i).toString('latin1'); buf = buf.subarray(i + 4); return out; }
        check(); await wait(ms);
      }
    },
    detach() {
      sock.removeListener('data', onData); sock.removeListener('error', onError); sock.removeListener('close', onClose);
      sock.on('error', () => {});
    }
  };
}

async function viaHttp(p, host, port, timeout) {
  const s = await tcpConnect(p.host, p.port, timeout);
  const r = reader(s);
  try {
    let req = `CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\nUser-Agent: ${UA}\r\n`;
    if (p.user !== null) req += `Proxy-Authorization: Basic ${Buffer.from(p.user + ':' + p.pass).toString('base64')}\r\n`;
    s.write(req + '\r\n');
    const head = await r.head(timeout);
    const line = head.split('\r\n')[0];
    const m = line.match(/^HTTP\/\d(?:\.\d)? (\d{3})/);
    if (!m) throw new Error('Not an HTTP proxy (unexpected reply)');
    const code = Number(m[1]);
    if (code === 407) throw new Error('The proxy needs a username and password, or the ones given are wrong');
    if (code !== 200) throw new Error(`The proxy refused to open a tunnel (${line})`);
    r.detach();
    return s;
  } catch (e) { s.destroy(); throw e; }
}

const SOCKS_ERR = {
  1: 'general failure', 2: 'blocked by the proxy rules', 3: 'network unreachable', 4: 'host unreachable',
  5: 'connection refused', 6: 'TTL expired', 7: 'command not supported', 8: 'address type not supported'
};
async function viaSocks5(p, host, port, timeout) {
  const s = await tcpConnect(p.host, p.port, timeout);
  const r = reader(s);
  try {
    const methods = p.user !== null ? [0x00, 0x02] : [0x00];
    s.write(Buffer.from([5, methods.length, ...methods]));
    const g = await r.take(2, timeout);
    if (g[0] !== 5) throw new Error('Not a SOCKS5 proxy');
    if (g[1] === 0xff) throw new Error('The SOCKS5 proxy needs a username and password');
    if (g[1] === 2) {
      if (p.user === null) throw new Error('The SOCKS5 proxy needs a username and password');
      const u = Buffer.from(p.user), pw = Buffer.from(p.pass);
      s.write(Buffer.concat([Buffer.from([1, u.length]), u, Buffer.from([pw.length]), pw]));
      const a = await r.take(2, timeout);
      if (a[1] !== 0) throw new Error('The SOCKS5 username or password was rejected');
    }
    const h = Buffer.from(host);
    s.write(Buffer.concat([Buffer.from([5, 1, 0, 3, h.length]), h, Buffer.from([port >> 8, port & 255])]));
    const rep = await r.take(4, timeout);
    if (rep[0] !== 5) throw new Error('Not a SOCKS5 proxy');
    if (rep[1] !== 0) throw new Error('The SOCKS5 proxy could not reach the test server: ' + (SOCKS_ERR[rep[1]] || 'code ' + rep[1]));
    const len = rep[3] === 1 ? 4 : rep[3] === 4 ? 16 : (await r.take(1, timeout))[0];
    await r.take(len + 2, timeout);
    r.detach();
    return s;
  } catch (e) { s.destroy(); throw e; }
}

async function openTunnel(p, state) {
  const kinds = p.kind === 'auto' ? (state.kind ? [state.kind] : ['http', 'socks5']) : [p.kind];
  const errs = [];
  for (const k of kinds) {
    try {
      const s = await (k === 'http' ? viaHttp : viaSocks5)(p, TH, TP, STEP_TIMEOUT);
      state.kind = k;
      return s;
    } catch (e) {
      errs.push({ k, msg: e.message });
      if (/refused the connection|could not be found|Timed out|unreachable/.test(e.message)) break;
    }
  }
  const specific = errs.filter(e => !/^(Not an HTTP|Not a SOCKS5|The proxy closed|The proxy did not answer)/.test(e.msg));
  if (specific.length) throw new Error(specific[0].msg);
  if (errs.length > 1) throw new Error('This does not look like an HTTP or SOCKS5 proxy (it did not answer either protocol correctly)');
  throw new Error(errs[0].msg);
}

function makeAgent(p, state) {
  const agent = new https.Agent({ keepAlive: true, maxSockets: 16 });
  agent.createConnection = function (opts, cb) {
    let called = false;
    const done = (e, s) => { if (called) return; called = true; cb(e, s); };
    openTunnel(p, state).then(sock => {
      const t = tls.connect({ socket: sock, servername: TH });
      t.once('secureConnect', () => done(null, t));
      t.once('error', e => { sock.destroy(); done(new Error('Secure connection through the proxy failed: ' + e.message)); });
    }).catch(e => done(e));
  };
  return agent;
}

/* ---------- Requests over the tunnel ---------- */
function getText(agent, p, timeout, signal) {
  return new Promise((resolve, reject) => {
    const r = https.request({ agent, host: TH, port: TP, method: 'GET', path: p, servername: TH,
      headers: { 'User-Agent': UA, Accept: '*/*' } }, resp => {
      const chunks = [];
      resp.on('data', d => chunks.push(d));
      resp.on('end', () => resolve({ status: resp.statusCode, body: Buffer.concat(chunks).toString() }));
      resp.on('error', reject);
    });
    r.setTimeout(timeout, () => r.destroy(new Error('The proxy took too long to respond')));
    r.on('error', reject);
    if (signal) signal.addEventListener('abort', () => r.destroy(new Error('aborted')), { once: true });
    r.end();
  });
}

function makeMeter(getBytes, onSpeed) {
  const t0 = Date.now(); let warmB = null, warmT = null; const win = [];
  const id = setInterval(() => {
    const now = Date.now(), b = getBytes();
    win.push([now, b]); while (win.length > 1 && now - win[0][0] > 1200) win.shift();
    if (warmB === null && now - t0 >= WARM_MS) { warmB = b; warmT = now; }
    const [t1, b1] = win[0];
    if (now > t1) onSpeed(((b - b1) * 8) / ((now - t1) / 1000) / 1e6);
  }, 250);
  return {
    stop() {
      clearInterval(id);
      const now = Date.now(), b = getBytes();
      const fromT = warmT ?? t0, fromB = warmB ?? 0;
      return ((b - fromB) * 8) / ((now - fromT) / 1000) / 1e6;
    }
  };
}

async function download(agent, emit, signal, streams = 4) {
  let bytes = 0, err = null, stop = false;
  const reqs = new Set();
  const meter = makeMeter(() => bytes, v => emit({ t: 'speed', phase: 'down', mbps: v }));
  const kill = () => { stop = true; reqs.forEach(r => r.destroy()); };
  const timer = setTimeout(kill, DOWN_MS);
  signal.addEventListener('abort', kill, { once: true });
  async function worker() {
    while (!stop && !err) {
      await new Promise(resolve => {
        const r = https.request({ agent, host: TH, port: TP, method: 'GET', servername: TH,
          path: `/__down?bytes=25000000&r=${crypto.randomBytes(4).toString('hex')}`,
          headers: { 'User-Agent': UA } }, resp => {
          if (resp.statusCode !== 200) { err = new Error('Test server answered HTTP ' + resp.statusCode); resp.resume(); return resolve(); }
          resp.on('data', d => { bytes += d.length; });
          resp.on('end', resolve); resp.on('close', resolve); resp.on('error', resolve);
        });
        reqs.add(r);
        r.on('error', e => { if (!stop) err = err || e; resolve(); });
        r.end();
      });
    }
  }
  await Promise.all(Array.from({ length: streams }, worker));
  clearTimeout(timer);
  const result = meter.stop();
  if (signal.aborted) throw new Error('aborted');
  if (bytes === 0) throw err || new Error('No data came through the proxy');
  return result;
}

async function upload(agent, emit, signal, streams = 3) {
  const CHUNK = crypto.randomBytes(65536);
  const TOTAL = 65536 * 128;                       // 8 MB per request
  let bytes = 0, err = null, stop = false;
  const reqs = new Set();
  const meter = makeMeter(() => bytes, v => emit({ t: 'speed', phase: 'up', mbps: v }));
  const kill = () => { stop = true; reqs.forEach(r => r.destroy()); };
  const timer = setTimeout(kill, UP_MS);
  signal.addEventListener('abort', kill, { once: true });
  async function worker() {
    while (!stop && !err) {
      await new Promise(resolve => {
        const r = https.request({ agent, host: TH, port: TP, method: 'POST', servername: TH,
          path: `/__up?r=${crypto.randomBytes(4).toString('hex')}`,
          headers: { 'User-Agent': UA, 'Content-Type': 'text/plain', 'Content-Length': TOTAL } }, resp => {
          resp.resume();
          resp.on('end', resolve); resp.on('close', resolve); resp.on('error', resolve);
        });
        reqs.add(r);
        r.on('error', e => { if (!stop) err = err || e; resolve(); });
        let sent = 0;
        (function pump() {
          while (sent < TOTAL && !stop) {
            const ok = r.write(CHUNK, () => { bytes += CHUNK.length; });
            sent += CHUNK.length;
            if (!ok) { r.once('drain', pump); return; }
          }
          if (!stop) r.end();
        })();
      });
    }
  }
  await Promise.all(Array.from({ length: streams }, worker));
  clearTimeout(timer);
  const result = meter.stop();
  if (signal.aborted) throw new Error('aborted');
  if (bytes === 0) throw err || new Error('Upload did not go through the proxy');
  return result;
}

/* ---------- The whole proxy test ---------- */
function directMeta() {
  return new Promise(resolve => {
    const r = https.get({ host: TH, port: TP, path: '/meta', headers: { 'User-Agent': UA } }, resp => {
      const c = []; resp.on('data', d => c.push(d));
      resp.on('end', () => { try { resolve(JSON.parse(Buffer.concat(c).toString())); } catch (e) { resolve(null); } });
    });
    r.setTimeout(6000, () => r.destroy());
    r.on('error', () => resolve(null));
  });
}

async function runTest(body, emit, signal) {
  const p = parseProxy(body.proxy, body.type);
  const state = { kind: p.kind === 'auto' ? null : p.kind };
  const agent = makeAgent(p, state);
  const alive = () => { if (signal.aborted) throw new Error('aborted'); };
  try {
    emit({ t: 'status', msg: `Connecting to ${p.host}:${p.port}…` });
    const t0 = Date.now();
    const first = await getText(agent, '/__down?bytes=0', STEP_TIMEOUT * 1.5, signal);
    alive();
    if (first.status !== 200) throw new Error('Test server answered HTTP ' + first.status + ' through the proxy');
    emit({ t: 'connect', ms: Date.now() - t0, type: state.kind });

    // Exit IP and location, compared with this computer's own address.
    try {
      const [via, direct] = await Promise.all([getText(agent, '/meta', 8000, signal), directMeta()]);
      const m = JSON.parse(via.body);
      const colo = m.colo && typeof m.colo === 'object' ? (m.colo.city || m.colo.iata) : m.colo;
      emit({ t: 'info', ip: m.clientIp, isp: m.asOrganization, city: m.city, country: m.country, edge: colo,
        sameAsDirect: !!(direct && direct.clientIp && direct.clientIp === m.clientIp) });
    } catch (e) { /* info is optional */ }
    alive();

    emit({ t: 'phase', phase: 'ping' });
    const samples = [];
    for (let i = 0; i < 10; i++) {
      const t = process.hrtime.bigint();
      await getText(agent, `/__down?bytes=0&r=${i}`, STEP_TIMEOUT, signal);
      samples.push(Number(process.hrtime.bigint() - t) / 1e6);
      alive();
    }
    const sorted = [...samples].sort((a, b) => a - b);
    let j = 0; for (let i = 1; i < samples.length; i++) j += Math.abs(samples[i] - samples[i - 1]);
    emit({ t: 'ping', ping: sorted[Math.floor(sorted.length / 2)], jitter: j / (samples.length - 1) });

    emit({ t: 'phase', phase: 'down' });
    emit({ t: 'result', phase: 'down', mbps: await download(agent, emit, signal) });

    emit({ t: 'phase', phase: 'up' });
    emit({ t: 'result', phase: 'up', mbps: await upload(agent, emit, signal) });

    emit({ t: 'done' });
  } finally { agent.destroy(); }
}

/* ---------- HTTP server ---------- */
const server = http.createServer(async (req, res) => {
  const host = (req.headers.host || '').split(':')[0];
  if (host !== 'localhost' && host !== '127.0.0.1') { res.writeHead(403); return res.end('Forbidden'); }
  const url = req.url.split('?')[0];

  if (req.method === 'GET' && url === '/api/hello') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    return res.end(JSON.stringify({ speedtest: true }));
  }

  if (req.method === 'GET' && (url === '/' || url === '/index.html' || url === '/speedtest.html')) {
    try {
      const html = fs.readFileSync(path.join(__dirname, 'speedtest.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(html);
    } catch (e) { res.writeHead(500); return res.end('speedtest.html must be in the same folder as server.js'); }
  }

  if (req.method === 'POST' && url === '/api/proxy-test') {
    const origin = req.headers.origin;
    if (origin && origin !== `http://${req.headers.host}`) { res.writeHead(403); return res.end('Forbidden'); }
    let raw = '';
    req.on('data', d => { raw += d; if (raw.length > 10000) req.destroy(); });
    req.on('end', async () => {
      let body;
      try { body = JSON.parse(raw); } catch (e) { res.writeHead(400); return res.end('Bad request'); }
      res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no' });
      const ac = new AbortController();
      res.on('close', () => ac.abort());
      const emit = ev => { if (!res.writableEnded && !res.destroyed) res.write(JSON.stringify(ev) + '\n'); };
      try { await runTest(body, emit, ac.signal); }
      catch (e) { if (!ac.signal.aborted) emit({ t: 'error', msg: e.message || String(e) }); }
      res.end();
    });
    return;
  }

  res.writeHead(404); res.end('Not found');
});

server.listen(PORT, BIND, () => {
  console.log(`Speed test is running: http://localhost:${PORT}`);
  console.log('Press Ctrl+C to stop.');
});

module.exports = { parseProxy };
