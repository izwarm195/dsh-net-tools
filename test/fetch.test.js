import { test } from 'node:test'
import assert from 'node:assert/strict'
import { connect } from 'node:net'
import { netFetch, resolveProxy, assertPublicTarget, proxyStatus } from '../lib/fetch.js'

const PROXY = 'http://127.0.0.1:7897'

/** Whether a local proxy is listening on 127.0.0.1:7897 (CI runners don't have one). */
function proxyAvailable() {
  return new Promise((resolve) => {
    const s = connect(7897, '127.0.0.1')
    s.setTimeout(1500)
    s.once('connect', () => { s.destroy(); resolve(true) })
    s.once('error', () => resolve(false))
    s.once('timeout', () => { s.destroy(); resolve(false) })
  })
}

const PROXY_AVAILABLE = await proxyAvailable()

test('resolveProxy reads HTTPS_PROXY env', () => {
  const p = resolveProxy(undefined, { HTTPS_PROXY: 'http://127.0.0.1:7897' })
  assert.ok(p)
  assert.equal(p.host, '127.0.0.1')
  assert.equal(p.port, 7897)
})

test('resolveProxy falls back to system proxy', () => {
  // No explicit/env proxy on a bare env; may pick up registry proxy on Windows.
  const p = resolveProxy(undefined, {})
  assert.ok(p === null || p.host)
})

test('assertPublicTarget rejects non-http(s)', () => {
  assert.throws(() => assertPublicTarget('ftp://example.com'), /unsupported scheme/)
})

test('assertPublicTarget rejects private addresses', () => {
  for (const u of ['http://127.0.0.1/x', 'http://localhost/x', 'http://10.0.0.1/x', 'http://192.168.1.1/x']) {
    assert.throws(() => assertPublicTarget(u, false), /private\/loopback/)
  }
  // allowPrivate bypasses
  assert.ok(assertPublicTarget('http://127.0.0.1/x', true))
})

test('netFetch fetches over proxy when env proxy is set', { timeout: 30_000, skip: !PROXY_AVAILABLE }, async () => {
  const r = await netFetch('https://www.gstatic.com/generate_204', {
    proxy: PROXY,
    maxBytes: 4096,
    timeoutMs: 15_000,
  })
  assert.equal(r.status, 204)
  assert.equal(r.ok, true)
  assert.equal(r.proxy, true)
})

test('netFetch follows redirects', { timeout: 30_000, skip: !PROXY_AVAILABLE }, async () => {
  const r = await netFetch(
    'https://github.com/anywhere-labs/deepseek-harness-desktop/raw/master/README.md',
    { proxy: PROXY, maxBytes: 2000, timeoutMs: 15_000 },
  )
  assert.ok(r.redirects >= 1)
  assert.ok(r.status === 200)
})

test('netFetch enforces size cap', { timeout: 30_000, skip: !PROXY_AVAILABLE }, async () => {
  const r = await netFetch('https://api.github.com/repos/deepseek-ai/deepseek-harness', {
    proxy: PROXY,
    maxBytes: 500,
    timeoutMs: 15_000,
  })
  assert.equal(r.truncated, true)
  assert.ok(r.body.length <= 500)
})

test('proxyStatus reports an effective proxy', () => {
  const s = proxyStatus({ HTTPS_PROXY: PROXY })
  assert.equal(s.effective, PROXY)
  assert.ok(s.note.length > 0)
})
