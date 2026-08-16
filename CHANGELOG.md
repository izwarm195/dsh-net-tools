# Changelog

All notable changes to dsh-net-tools are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-08-16

### Added

- `net_fetch` tool: HTTP(S) fetch through the user's local proxy via a manual
  CONNECT tunnel (no schannel, zero dependencies); follows redirects, enforces
  timeouts, size caps and SSRF guards.
- `net_proxy_status` tool: reports which proxy DSH processes will use (process
  env, user env, Windows system proxy) and probes its reachability.
- `cordis.patch.yml` bundle manifest so the package installs via
  `dsh plugin add`.

### Fixed

- Tool outputs strictly match the declared lossless-JSON output schema: no
  `undefined`-valued fields, no undeclared keys (`headers`).
- Proxy reachability check uses a proper ESM `import { connect } from 'node:net'`
  instead of a bare `require` call that threw in the ESM host.

### Tests

- Unit tests for proxy resolution, SSRF guards, CONNECT-tunnel fetching,
  redirects and size caps; network tests auto-skip when no local proxy is
  present (CI-friendly).
