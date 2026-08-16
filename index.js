// dsh-net-tools: reliable outbound networking for sandboxed agents.
// Tools run in the DSH Host process (Node.js) and tunnel through the user's
// local HTTP proxy, bypassing the schannel TLS failure caused by the file
// sandbox.

import { connect } from 'node:net'
import { netFetch, proxyStatus, resolveProxy } from './lib/fetch.js'

export const name = 'dsh-net-tools'
export const inject = ['tools']

export function apply(ctx) {
  ctx.tools.register({
    name: 'net_fetch',
    description:
      'Fetch an HTTP(S) URL through the user\'s local proxy and return the response body as text. Use when web_search snippets are not enough, when you need raw page/API/JSON content, or whenever a sandboxed shell cannot reach the network. Automatically uses the system/user proxy (CONNECT tunnel); never uses Windows schannel, so it works inside the DSH file sandbox. Follows redirects (max 5), enforces timeouts and size caps, and blocks private/loopback targets unless allowPrivate is true.',
    parameters: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'http:// or https:// URL to fetch' },
        proxy: { type: 'string', description: 'Optional explicit proxy URL (e.g. http://127.0.0.1:7897); defaults to env or Windows system proxy' },
        allowPrivate: { type: 'boolean', description: 'Allow private/loopback targets (SSRF guard); default false' },
        maxBytes: { type: 'integer', description: 'Maximum response bytes to read; default 1048576 (1 MiB)' },
        timeoutMs: { type: 'integer', description: 'Timeout in milliseconds; default 30000' },
      },
      required: ['url'],
      additionalProperties: false,
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' },
          status: { type: 'integer' },
          url: { type: 'string' },
          contentType: { type: 'string' },
          body: { type: 'string', description: 'Response body as UTF-8 text' },
          truncated: { type: 'boolean' },
          redirects: { type: 'integer' },
          proxy: { type: 'boolean', description: 'Whether the request went through a proxy' },
          elapsedMs: { type: 'integer' },
          error: { type: 'string' },
        },
        required: ['ok', 'status', 'url', 'body'],
        additionalProperties: false,
      },
      render: (_args, value) => [
        {
          type: 'text',
          text: value.error
            ? `net_fetch: ${value.error}`
            : `[${value.status}] ${value.url}${value.proxy ? ' (via proxy)' : ''} ${value.elapsedMs}ms${value.truncated ? ' [truncated]' : ''}\n\n${value.body.slice(0, 2000)}`,
        },
      ],
    },
    isConcurrencySafe: () => true,
    async execute(args) {
      try {
        const result = await netFetch(args.url, {
          proxy: args.proxy,
          allowPrivate: args.allowPrivate,
          maxBytes: args.maxBytes,
          timeoutMs: args.timeoutMs,
        })
        // The declared output schema is closed (additionalProperties: false)
        // and lossless-JSON rejects `undefined` values, so return exactly the
        // schema's fields: drop `headers` and omit `error` on success.
        const { headers, ...rest } = result
        return rest
      } catch (err) {
        return {
          ok: false,
          status: 0,
          url: args.url,
          contentType: '',
          body: '',
          truncated: false,
          redirects: 0,
          proxy: !!resolveProxy(args.proxy),
          elapsedMs: 0,
          error: err instanceof Error ? err.message : String(err),
        }
      }
    },
  })

  ctx.tools.register({
    name: 'net_proxy_status',
    description:
      'Report which HTTP proxy DSH processes will use for outbound networking (process env, user-level env, and the Windows system proxy) and whether it is reachable. Use before net_fetch or any outbound tool when network behavior is unexpected.',
    parameters: {
      type: 'object',
      properties: {
        checkReachability: { type: 'boolean', description: 'Also try connecting to the proxy and to a probe URL; default true' },
      },
      additionalProperties: false,
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          processEnvProxy: { oneOf: [{ type: 'string' }, { type: 'null' }] },
          userEnvProxy: { oneOf: [{ type: 'string' }, { type: 'null' }] },
          systemProxy: { oneOf: [{ type: 'string' }, { type: 'null' }] },
          effectiveProxy: { oneOf: [{ type: 'string' }, { type: 'null' }] },
          note: { type: 'string' },
          proxyReachable: { oneOf: [{ type: 'boolean' }, { type: 'null' }] },
          probe: {
            type: 'object',
            properties: {
              url: { type: 'string' },
              status: { type: 'integer' },
              ok: { type: 'boolean' },
            },
            additionalProperties: false,
          },
          error: { type: 'string' },
        },
        required: ['effectiveProxy', 'note'],
        additionalProperties: false,
      },
      render: (_args, value) => [
        {
          type: 'text',
          text: [
            `net_proxy_status: ${value.note}`,
            `  process env proxy: ${value.processEnvProxy ?? '(none)'}`,
            `  user env proxy:    ${value.userEnvProxy ?? '(none)'}`,
            `  system proxy:      ${value.systemProxy ?? '(none)'}`,
            `  effective:         ${value.effectiveProxy ?? '(direct)'}`,
            value.proxyReachable === null || value.proxyReachable === undefined
              ? ''
              : `  proxy reachable:   ${value.proxyReachable}`,
            value.probe ? `  probe: [${value.probe.status}] ${value.probe.url} ok=${value.probe.ok}` : '',
            value.error ? `  error: ${value.error}` : '',
          ].filter(Boolean).join('\n'),
        },
      ],
    },
    isConcurrencySafe: () => true,
    async execute(args) {
      const status = proxyStatus()
      const result = {
        processEnvProxy: status.processEnv,
        userEnvProxy: status.userEnv,
        systemProxy: status.systemProxy,
        effectiveProxy: status.effective,
        note: status.note,
        proxyReachable: null,
      }
      // `probe` / `error` are set only when present: lossless JSON rejects
      // `undefined` properties, and the output schema is closed.
      if (args.checkReachability !== false && status.effective) {
        try {
          const parsed = new URL(/^[a-z]+:\/\//i.test(status.effective) ? status.effective : `http://${status.effective}`)
          const socket = await new Promise((resolve, reject) => {
            const s = connect(Number(parsed.port) || 80, parsed.hostname, () => resolve(s))
            s.once('error', reject)
          })
          socket.destroy()
          result.proxyReachable = true
        } catch {
          result.proxyReachable = false
        }
      }
      if (args.checkReachability !== false) {
        try {
          const probe = await netFetch('https://www.gstatic.com/generate_204', {
            proxy: status.effective,
            timeoutMs: 10_000,
            maxBytes: 4096,
          })
          result.probe = { url: 'https://www.gstatic.com/generate_204', status: probe.status, ok: probe.ok }
        } catch (err) {
          result.error = err instanceof Error ? err.message : String(err)
        }
      }
      return result
    },
  })
}
