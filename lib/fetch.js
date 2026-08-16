// dsh-net-tools: proxy-aware HTTP(S) fetching with zero dependencies.
// Runs in the DSH Host process (Node.js), so TLS never goes through Windows
// schannel and is unaffected by the file sandbox.

import { connect } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import { execFileSync } from 'node:child_process'

export const MAX_REDIRECTS = 5
export const DEFAULT_MAX_BYTES = 1024 * 1024 // 1 MiB
export const DEFAULT_TIMEOUT_MS = 30_000

// ---------------------------------------------------------------------------
// Proxy discovery
// ---------------------------------------------------------------------------

/** User-level + process env names we consult, in preference order. */
const PROXY_ENV_NAMES = [
  ['HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY'],
  ['https_proxy', 'http_proxy', 'all_proxy'],
]

/** Read a proxy candidate from env (uppercase first, then lowercase). */
function proxyFromEnv(env = process.env) {
  for (const [upper, lower] of PROXY_ENV_NAMES) {
    const v = env[upper] ?? env[lower]
    if (v && v.trim().length > 0) return v.trim()
  }
  return undefined
}

/** Read the Windows system proxy (Internet Settings registry). */
function systemProxyFromRegistry() {
  const key = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'
  let out = ''
  try {
    out = execFileSync('reg', ['query', key, '/v', 'ProxyEnable', '/t', 'REG_DWORD'], { windowsHide: true })
  } catch {
    return undefined
  }
  if (!/0x1\b/.test(out)) return undefined // ProxyEnable != 1
  try {
    out = execFileSync('reg', ['query', key, '/v', 'ProxyServer'], { windowsHide: true })
  } catch {
    return undefined
  }
  const m = /ProxyServer\s+REG_SZ\s+([^\r\n]+)/.exec(out)
  if (!m) return undefined
  const server = m[1].trim()
  if (!server) return undefined
  // Registry may list "host:port" (HTTP proxy) or "http=host:port;https=host:port".
  const httpProxy = /(?:^|;)\s*https?=([^;]+)/.exec(server)
  return httpProxy ? httpProxy[1].trim() : server
}

/**
 * Resolve the proxy to use, in order: explicit argument → env → Windows system.
 * Returns { url, host, port } or null when no proxy is configured.
 */
export function resolveProxy(explicit, env = process.env) {
  const raw = explicit ?? proxyFromEnv(env) ?? systemProxyFromRegistry()
  if (!raw) return null
  let u
  try {
    u = new URL(/^[a-z]+:\/\//i.test(raw) ? raw : `http://${raw}`)
  } catch {
    return null
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
  const port = Number(u.port) || (u.protocol === 'https:' ? 443 : 80)
  return { url: raw, host: u.hostname, port }
}

// ---------------------------------------------------------------------------
// SSRF guards
// ---------------------------------------------------------------------------

const PRIVATE_IP_RE = /^(?:10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/
const LOOPBACK_HOSTS = new Set(['localhost', '::1'])

function isPrivateHost(host) {
  const h = host.toLowerCase()
  if (LOOPBACK_HOSTS.has(h) || h === '0.0.0.0' || h.endsWith('.local')) return true
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) return PRIVATE_IP_RE.test(h)
  return false // hostnames resolved later are guarded again
}

/** Reject a target that is not http(s) or is a private/loopback address. */
export function assertPublicTarget(rawUrl, allowPrivate) {
  let u
  try {
    u = new URL(rawUrl)
  } catch {
    throw new Error(`net_fetch: invalid URL: ${rawUrl}`)
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new Error(`net_fetch: unsupported scheme ${u.protocol}; only http/https allowed`)
  }
  if (!allowPrivate && isPrivateHost(u.hostname)) {
    throw new Error(`net_fetch: target ${u.hostname} is a private/loopback address; pass allowPrivate:true to fetch it`)
  }
  return u
}

// ---------------------------------------------------------------------------
// CONNECT tunnel fetch
// ---------------------------------------------------------------------------

/** Perform one request through a CONNECT proxy tunnel (or direct). */
function requestViaTunnel(target, proxy, { method, headers, timeoutMs, maxBytes }) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      destroySocket()
      reject(new Error(`net_fetch: request timed out after ${timeoutMs}ms`))
    }, timeoutMs)

    let socket

    function destroySocket() {
      try {
        socket?.destroy()
      } catch {
        /* already gone */
      }
    }

    // Plain HTTP request line: through a proxy it's the absolute URL, direct it's origin-form.
    const requestTarget = proxy ? `${target.origin}${target.path}` : target.path
    const reqHeaders = {
      Host: target.host,
      'User-Agent': 'dsh-net-tools/0.1',
      Accept: '*/*',
      'Accept-Encoding': 'identity',
      Connection: 'close',
      ...headers,
    }
    const head = Object.entries(reqHeaders)
      .map(([k, v]) => `${k}: ${v}`)
      .join('\r\n')

    const writeRequest = (stream) => {
      stream.write(`${method} ${requestTarget} HTTP/1.1\r\n${head}\r\n\r\n`)
      readResponse(stream)
    }

    const beginTls = () => {
      const tlsSocket = tlsConnect(
        { socket, servername: target.host, ALPNProtocols: ['http/1.1'] },
        () => {
          tlsSocket.once('error', onError)
          writeRequest(tlsSocket)
        },
      )
      tlsSocket.once('error', onError)
      socket = tlsSocket
    }

    const onError = (err) => {
      clearTimeout(timer)
      reject(err)
    }

    if (target.secure) {
      // HTTPS: TCP → CONNECT (when proxied) → TLS → request.
      if (proxy) {
        socket = connect(proxy.port, proxy.host)
        socket.once('error', onError)
        socket.once('connect', () => {
          socket.write(`CONNECT ${target.host}:${target.port} HTTP/1.1\r\nHost: ${target.host}:${target.port}\r\n\r\n`)
        })
        let handshake = ''
        socket.on('data', function onHandshake(chunk) {
          handshake += chunk.toString('latin1')
          const idx = handshake.indexOf('\r\n\r\n')
          if (idx === -1) return
          socket.removeListener('data', onHandshake)
          const statusLine = handshake.slice(0, handshake.indexOf('\r\n'))
          if (!/^HTTP\/1\.[01] 200\b/.test(statusLine)) {
            clearTimeout(timer)
            socket.destroy(new Error(`net_fetch: proxy CONNECT failed: ${statusLine}`))
            return
          }
          // Bytes after the CONNECT response head are the start of the TLS
          // stream; put them back so the TLS layer consumes them.
          if (idx + 4 < handshake.length) {
            socket.unshift(Buffer.from(handshake.slice(idx + 4), 'latin1'))
          }
          beginTls()
        })
      } else {
        socket = connect(target.port, target.host)
        socket.once('error', onError)
        socket.once('connect', beginTls)
      }
    } else {
      // Plain HTTP: never TLS; through a proxy send the absolute URL.
      socket = connect(proxy ? proxy.port : target.port, proxy ? proxy.host : target.host)
      socket.once('error', onError)
      socket.once('connect', () => {
        socket.once('error', onError)
        writeRequest(socket)
      })
    }

    function readResponse(stream) {
      const chunks = []
      let total = 0
      let headerEnd = -1
      let headerBuf = Buffer.alloc(0)
      stream.on('data', (chunk) => {
        if (headerEnd === -1) {
          headerBuf = Buffer.concat([headerBuf, chunk])
          const idx = headerBuf.indexOf('\r\n\r\n')
          if (idx !== -1) {
            headerEnd = idx
            const rest = headerBuf.slice(idx + 4)
            headerBuf = headerBuf.slice(0, idx)
            chunks.push(rest)
            total += rest.length
          }
        } else {
          chunks.push(chunk)
          total += chunk.length
        }
        if (total > maxBytes) {
          clearTimeout(timer)
          stream.destroy()
          resolve({
            truncated: true,
            raw: Buffer.concat(chunks).slice(0, maxBytes),
            head: headerBuf.toString('latin1'),
          })
        }
      })
      stream.once('end', () => {
        clearTimeout(timer)
        resolve({ truncated: false, raw: Buffer.concat(chunks), head: headerBuf.toString('latin1') })
      })
    }
  })
}

/** Parse the raw response head into { status, headers } and redirect location. */
function parseHead(head) {
  const lines = head.split('\r\n')
  const statusLine = lines[0] || ''
  const m = /^HTTP\/1\.[01]\s+(\d{3})/.exec(statusLine)
  const status = m ? Number(m[1]) : 0
  const headers = {}
  for (const line of lines.slice(1)) {
    const ci = line.indexOf(':')
    if (ci === -1) continue
    const name = line.slice(0, ci).trim().toLowerCase()
    headers[name] = line.slice(ci + 1).trim()
  }
  return { status, headers }
}

/**
 * Fetch an HTTP(S) URL through the user's proxy, following redirects.
 * @returns {Promise<{ok:boolean,status:number,url:string,headers:object,contentType:string,body:string,truncated:boolean,redirects:number,proxy:boolean,elapsedMs:number}>}
 */
export async function netFetch(rawUrl, opts = {}) {
  const {
    proxy: explicitProxy,
    allowPrivate = false,
    maxBytes = DEFAULT_MAX_BYTES,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    headers = {},
  } = opts

  const started = Date.now()
  const isLoopback = /^127\.|^localhost$/i.test(new URL(rawUrl).hostname)
  const proxy = isLoopback && allowPrivate ? null : resolveProxy(explicitProxy)
  let url = assertPublicTarget(rawUrl, allowPrivate)
  let redirects = 0

  for (;;) {
    const port = Number(url.port) || (url.protocol === 'https:' ? 443 : 80)
    const target = {
      host: url.hostname,
      port,
      path: url.pathname + url.search,
      secure: url.protocol === 'https:',
      origin: `${url.protocol}//${url.host}`,
    }

    const res = await requestViaTunnel(target, proxy, {
      method: 'GET',
      headers,
      timeoutMs,
      maxBytes,
    })

    const { status, headers: respHeaders } = parseHead(res.head)
    const location = respHeaders.location

    if (status >= 300 && status < 400 && location) {
      if (redirects >= MAX_REDIRECTS) {
        return {
          ok: false, status, url: rawUrl, headers: respHeaders,
          contentType: respHeaders['content-type'] ?? '',
          body: `Too many redirects (max ${MAX_REDIRECTS})`, truncated: false,
          redirects, proxy: !!proxy, elapsedMs: Date.now() - started,
        }
      }
      redirects += 1
      url = assertPublicTarget(new URL(location, url).toString(), allowPrivate)
      continue
    }

    const contentType = respHeaders['content-type'] ?? ''
    const body = res.raw.toString('utf8')
    return {
      ok: status >= 200 && status < 300,
      status,
      url: rawUrl,
      headers: respHeaders,
      contentType,
      body,
      truncated: res.truncated,
      redirects,
      proxy: !!proxy,
      elapsedMs: Date.now() - started,
    }
  }
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/** Report proxy configuration from env (user + process) and the system proxy. */
export function proxyStatus(env = process.env) {
  const explicitEnv = proxyFromEnv(env)
  const system = systemProxyFromRegistry()
  const userEnv = proxyFromEnv(collectUserEnv())
  return {
    processEnv: explicitEnv ?? null,
    userEnv: userEnv ?? null,
    systemProxy: system ?? null,
    effective: explicitEnv ?? userEnv ?? system ?? null,
    note: explicitEnv
      ? 'Process environment HTTP(S)_PROXY is set.'
      : userEnv
        ? 'User-level HTTP(S)_PROXY environment variable is set.'
        : system
          ? 'Using Windows system proxy from Internet Settings.'
          : 'No proxy configured; requests will go direct.',
  }
}

/** Read user-level env vars (registry-backed) for HTTP(S)_PROXY. */
function collectUserEnv() {
  const env = {}
  for (const name of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) {
    try {
      const v = execFileSync('reg', [
        'query',
        'HKCU\\Environment',
        '/v',
        name,
      ], { windowsHide: true })
      const m = /REG_[A-Z_]+\s+([^\r\n]+)/.exec(v)
      if (m) env[name] = m[1].trim()
    } catch {
      // not set
    }
  }
  return env
}
