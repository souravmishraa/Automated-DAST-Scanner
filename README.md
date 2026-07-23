# security-framework

A plug-and-play website security scanning framework for Node.js. Give it a
URL (and, optionally, credentials), and it orchestrates **Katana** (crawling),
**OWASP ZAP** (DAST), and **Nuclei** (template-based vuln scanning) end to
end — then hands you back a single interactive HTML dashboard, a JSON
report, and a SARIF file for GitHub code scanning.

> ⚠️ **Only scan applications you own or are explicitly authorized to test.**
> Active scanning (ZAP active scan, Nuclei) sends real attack payloads and
> can affect target availability. Get written authorization first.

---

## Table of contents

- [Why this exists](#why-this-exists)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Authentication](#authentication)
- [Configuration reference](#configuration-reference)
- [CLI reference](#cli-reference)
- [Output / reports](#output--reports)
- [Testing](#testing)
- [Running in GitHub Actions](#running-in-github-actions)
- [Docker](#docker)
- [Folder structure](#folder-structure)
- [Troubleshooting](#troubleshooting)
- [Extending the framework](#extending-the-framework)

---

## Why this exists

Setting up ZAP contexts, Nuclei template sets, and crawler configs by hand
for every app is slow and error-prone. This framework takes **one input**
(a target URL, plus optional auth) and internally:

1. Builds the right headers / ZAP auth context for your auth type
2. Crawls the app with Katana (including JS-discovered routes and forms)
3. Auto-discovers Swagger/OpenAPI specs and imports hidden API endpoints
4. Merges + deduplicates every discovered endpoint
5. Drives OWASP ZAP in headless Automation Framework mode (passive + active
   scan) against that endpoint set, using a ZAP plan it generates for you
6. Runs Nuclei against the same endpoint set with official templates
7. Normalizes every tool's output into one common finding schema
8. Renders a polished, dependency-free HTML dashboard, plus JSON and SARIF

You never touch ZAP contexts, Nuclei flags, or Katana crawl config directly.

## Architecture

```
CLI
 └─ Configuration Loader        (merges defaults + your config/flags, validates)
     └─ Authentication Module   (translates one auth block into headers + ZAP auth plan)
         └─ Katana Crawl        (URLs, params, forms, JS-discovered routes)
             └─ Swagger/OpenAPI Discovery
                 └─ Endpoint Merger      -> master-endpoints.json
                     └─ OWASP ZAP (Automation Framework, headless)
                         └─ Nuclei (official templates)
                             └─ Result Normalizer   -> common schema
                                 ├─ Custom HTML Report (dashboard)
                                 ├─ JSON Report
                                 └─ SARIF Report (GitHub code scanning)
```

Every module under `core/` is independent and reusable on its own — e.g.
you can `require('security-framework/core/normalizer/normalizer')` in your
own scripts.

## Requirements

The framework itself only needs Node.js. The scanning *engines* are
external CLI tools it shells out to — install what you need:

| Tool                | Required for         | Install |
|----------------------|----------------------|---------|
| Node.js >= 18         | the framework itself | https://nodejs.org |
| [Katana](https://github.com/projectdiscovery/katana) | crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | template scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| [Docker](https://docker.com) **or** a local [OWASP ZAP](https://www.zaproxy.org/download/) install | DAST scanning | `docker pull zaproxy/zap-stable` (default mode) |

**The framework degrades gracefully**: if a tool isn't installed, that
step is skipped with a clear warning in the console and the pipeline
continues with whatever tools *are* available, rather than crashing.

## Installation

```bash
npm install security-framework
```

or run it without installing, via `npx`:

```bash
npx security-framework scan https://example.com
```

For local development on this repo:

```bash
git clone <this-repo>
cd security-framework
npm install
```

## Quick start

```bash
# Simplest possible scan - no auth
npx security-framework scan https://example.com

# Using a config file
npx security-framework scan examples/config.simple.json

# Overriding just the target inline
npx security-framework scan --target https://example.com

# Attach an auth block from a separate file (keeps secrets out of your main config)
npx security-framework scan https://example.com --auth examples/auth.basic.json

# Only fail the process (non-zero exit code) on high or above
npx security-framework scan https://example.com --fail-on high

# Passive-only (skip ZAP active scan) - useful for a quick, low-impact pass
npx security-framework scan https://example.com --no-active-scan
```

### Zero-argument mode (drop it into any project)

For repeatable use inside a host project, skip passing a target/config every time:
drop a `security-framework.config.json` (see
[`examples/security-framework.config.json`](examples/security-framework.config.json))
in the project root, then just run:

```bash
npx security-framework scan
```

`security-framework` auto-discovers `security-framework.config.json` (or
`.security-framework.json`) in the current working directory, the same way
ESLint/Prettier/Jest discover their own config files — no framework source
changes needed per project, only a config file per project. An explicit
target, `--target`, or config path always takes priority over the
auto-discovered file.

Every scan writes to a timestamped folder under `./output/`, e.g.:

```
output/example.com_2026-07-07T05-44-52-000Z/
  katana-urls.txt
  urls.json
  swagger-endpoints.json
  master-endpoints.json
  master-endpoints.txt
  zap-plan.yaml
  zap-report.json
  zap-report.sarif.json
  nuclei-report.jsonl
  nuclei-report.sarif.json
  report.json
  report.sarif
  report.html          <-- open this
```

A sample of the final reports (from mock data, so you can see the format
without running a real scan) is in [`examples/sample-output/`](examples/sample-output).

## Authentication

Supply **one** `authentication` block; the framework generates everything
Katana, ZAP, and Nuclei need from it. Supported types:

<details>
<summary><strong>none</strong> (default)</summary>

```json
{ "type": "none" }
```
</details>

<details>
<summary><strong>basic</strong></summary>

```json
{ "type": "basic", "username": "admin", "password": "secret" }
```
</details>

<details>
<summary><strong>bearer</strong></summary>

```json
{ "type": "bearer", "token": "eyJhbGciOi..." }
```
</details>

<details>
<summary><strong>apiKey</strong></summary>

```json
{ "type": "apiKey", "apiKeyHeader": "X-API-Key", "apiKeyValue": "..." }
```
</details>

<details>
<summary><strong>cookie</strong> (pre-authenticated session)</summary>

```json
{ "type": "cookie", "cookie": "sessionid=abc123; other=value" }
```
</details>

<details>
<summary><strong>form</strong> (login page - drives ZAP's stateful form auth)</summary>

```json
{
  "type": "form",
  "loginUrl": "https://example.com/login",
  "username": "user@example.com",
  "password": "secret",
  "usernameField": "email",
  "passwordField": "password",
  "loggedInIndicator": "Sign out",
  "loggedOutIndicator": "Sign in"
}
```
</details>

<details>
<summary><strong>oauth</strong> (pre-fetched token, treated like bearer)</summary>

```json
{ "type": "oauth", "token": "..." }
```
</details>

Header-based types (`basic`, `bearer`, `apiKey`, `cookie`, `oauth`) are
injected as a static header on every request Katana, ZAP, and Nuclei make.
`form` auth is session-based and drives ZAP's Automation Framework form-login
+ verification flow, with a `scanner-user` context user.

**Never commit real credentials.** Use `--auth path/to/secret.json` (git-
ignored) or environment variable substitution in your own CI secrets store,
as shown in the bundled GitHub Actions workflow.

## Configuration reference

Full schema, with defaults, lives in
[`config/default.config.json`](config/default.config.json). Your config
file only needs to specify what you want to override — everything else
falls back to sane defaults. Key sections:

| Key | Purpose |
|---|---|
| `target` | The website URL to scan (required) |
| `authentication` | See [Authentication](#authentication) |
| `crawler.katana` | depth, concurrency, rate limit, JS crawling, form extraction |
| `apiDiscovery` | enable/disable + which Swagger/OpenAPI paths to probe |
| `zap` | execution mode (`docker`/`local`), passive/active toggle, durations |
| `nuclei` | severities, template tags, rate limit, concurrency |
| `reporting` | output dir, which formats to write, branding (company name/logo/color) |
| `failOn` | exit code threshold: `critical` \| `high` \| `medium` \| `low` \| `info` \| `none` |

See [`examples/`](examples) for full worked configs (simple, form-auth, API
bearer-token).

## CLI reference

```
security-framework scan [targetOrConfig]     Run a full scan
  --target <url>          Target URL (overrides config/positional arg)
  --auth <path>            JSON file containing just the "authentication" block
  --fail-on <severity>     critical|high|medium|low|info|none (default: critical)
  --output <dir>           Base output directory (default: ./output)
  --no-active-scan         Passive scan only, skip ZAP active scan
  --no-open                Don't auto-open the HTML report in your browser when the scan finishes

security-framework report <report.json>      Regenerate HTML/SARIF from an existing report.json
  --output <dir>           Where to write the regenerated reports
  --no-open                Don't auto-open the HTML report once regenerated

security-framework clean                     Remove everything under ./output
  --output <dir>

security-framework --version                 Print the installed version
```

By default, `scan` and `report` open `report.html` in your OS's default
browser as soon as it's written — pass `--no-open` to skip that (e.g. in CI).

## Output / reports

- **`report.html`** — a self-contained, dependency-free dashboard: severity
  summary cards, an SVG donut chart, search + severity/tool filters,
  expandable finding details (URL, parameter, evidence, CWE/CVE,
  remediation), dark/light mode, print-friendly styling, and buttons to
  download the JSON/SARIF alongside it. Nothing loads from a CDN, so it
  works fully offline and can be emailed or archived as-is.
- **`report.json`** — the normalized finding schema (see below), plus a
  summary object. Safe to feed into your own tooling.
- **`report.sarif`** — SARIF 2.1.0, ready for
  `github/codeql-action/upload-sarif` so findings show up in GitHub's
  Security tab.

Normalized finding schema:

```json
{
  "id": "a1b2c3d4e5f6...",
  "tool": "zap | nuclei",
  "severity": "critical | high | medium | low | info",
  "category": "string",
  "title": "string",
  "description": "string",
  "url": "string",
  "parameter": "string | null",
  "evidence": "string | null",
  "recommendation": "string",
  "cwe": "CWE-79 | null",
  "cve": "CVE-2024-0001 | null",
  "references": ["string", "..."]
}
```

## Testing

There's a small automated test suite in the `test/` folder that checks the
config-loading logic (merging defaults, validating input, etc.) works the
way it should. Run it with:

```bash
npm test
```

This doesn't scan anything or need Katana/ZAP/Nuclei installed — it just
checks the framework's own internal logic.

## Running in GitHub Actions

A ready-to-use workflow is at
[`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml).
It runs on push/PR/manual dispatch, installs Katana + Nuclei, pulls the ZAP
Docker image, runs the exact same `scan` command you'd run locally,
uploads the SARIF to GitHub's Security tab, and attaches the full report
folder as a downloadable artifact.

Configure the target via the repo variable `SECURITY_SCAN_TARGET` or a
manual `workflow_dispatch` input. Store any auth credentials as repo
secrets (`SCAN_AUTH_USERNAME`, `SCAN_AUTH_PASSWORD`, `SCAN_AUTH_TOKEN`) and
wire them into an `--auth` file at scan time if your target needs them.

## Docker

An optional `Dockerfile` bundles the framework with Katana + Nuclei
pre-installed (ZAP still runs via the host's Docker daemon, mounted in):

```bash
docker build -t security-framework .
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/output:/app/output" \
  security-framework scan https://example.com
```

## Folder structure

```
security-framework/
  index.js                     Programmatic entry point (what you get from require('security-framework'))
  bin/cli.js                   CLI entry point
  config/default.config.json   Full default schema
  core/
    configLoader.js            Loads + merges + validates config
    auth/authManager.js         One auth block -> headers + ZAP auth plan
    crawler/
      katanaRunner.js           Katana wrapper
      swaggerDiscovery.js       Swagger/OpenAPI probing + parsing
      endpointMerger.js         Dedup + normalize discovered endpoints
    zap/
      zapPlanBuilder.js         Builds a ZAP Automation Framework plan
      zapRunner.js              Executes ZAP (docker or local) against the plan
    nuclei/nucleiRunner.js       Nuclei wrapper
    normalizer/normalizer.js    Common finding schema + severity normalization
    reporter/
      jsonReporter.js
      sarifReporter.js
      htmlReporter.js            Fills templates/report.template.html
      index.js                   Orchestrates all three formats
    utils/
      logger.js                  Console logging helper
      exec.js                    Runs external CLI tools + retry logic
      fsHelpers.js                Small file read/write/exists helpers
      htmlForm.js                 Reads a classic login page's <form> so "form" auth
                                   only needs a URL + username/password, nothing else
    index.js                     The 8-step pipeline orchestrator
  templates/report.template.html Dashboard HTML/CSS/JS (no CDN dependencies)
  examples/                      Worked config files + sample-output/
  test/                         Automated tests (run with `npm test`)
  .github/workflows/             Ready-to-use GitHub Actions workflow
  output/                        Scan runs land here (git-ignored)
```

## Troubleshooting

**"Binary not found: katana / nuclei"**
The corresponding tool isn't installed or isn't on `PATH`. The framework
will skip that step and keep going — install the tool (see
[Requirements](#requirements)) for complete results.

**ZAP step is skipped**
By default ZAP runs via Docker (`zap.mode: "docker"`). Make sure Docker is
running and you can `docker pull zaproxy/zap-stable`. To use a local ZAP
install instead, set `"zap": { "mode": "local" }` in your config and ensure
`zap.sh` (or `zap.bat` on Windows) is on `PATH`.

**Scan takes a long time / times out**
Tune `zap.spiderMaxDurationMinutes`, `zap.activeScanMaxDurationMinutes`,
`crawler.katana.timeoutSeconds`, and `nuclei.timeoutSeconds` in your
config. Larger sites need more time; CI runners may need a longer
`timeout-minutes` on the job too.

**Form login isn't authenticating in ZAP**
Set `loggedInIndicator` / `loggedOutIndicator` to a string that reliably
appears only when logged in/out (e.g. a "Sign out" link) — without one,
ZAP falls back to a slower polling-based verification.

**Too many low-value findings**
Narrow `nuclei.severities` (e.g. `["high", "critical"]`) or
`nuclei.templates` tags, and set `zap.ajaxSpider: false` (default) unless
the target is a heavy JS SPA that the regular spider can't traverse.

**CI fails the build unexpectedly**
That's `failOn` doing its job — the process exit code is non-zero when
findings at/above the configured severity exist. Set `--fail-on none` (or
`"failOn": "none"` in config) if you just want reports without gating CI.

## Extending the framework

Every module in `core/` exports plain functions/classes with no hidden
global state, so you can:

- Integrate it into any Node.js project as a dependency and call the pipeline
  programmatically from your own app, CI job, or server.
- Swap in custom scanners, reporters, or auth handlers by replacing the
  relevant modules in `core/`.
- Build plugin-style workflows around the normalized finding schema without
  needing to understand the internals of Katana, ZAP, or Nuclei.

### Programmatic integration example

```js
const { runScan, generateReports } = require('security-framework');

(async () => {
  const { normalizedResult, reportPaths } = await runScan('https://example.com', {
    reporting: { outputDir: './output' }
  });

  console.log(normalizedResult.summary);
  console.log(reportPaths);
})();
```

### Plugin-style design goals

This framework is meant to behave like a reusable security pipeline:

- install it as a dependency
- configure it once
- plug it into your app or CI flow
- consume the generated reports and normalized findings

That keeps the scanner opinionated, but the integration surface simple.


- Add a new report format: drop a new file in `core/reporter/`, wire it
  into `core/reporter/index.js`.
- Add a new auth type: extend `AuthManager` (`getHttpHeaders()` and
  `toZapAuthPlan()`), then add validation to `configLoader.js`.
- Swap ZAP execution modes: `ZapRunner` already supports `docker` and
  `local`; add a third mode by branching in `run()`.
- Consume the normalized schema in your own tooling — `core/normalizer`
  is fully decoupled from the reporters.

---

Built to be a single, opinionated pipeline — not a config-your-own-scanner
toolkit. If you need something the framework doesn't expose, open the
relevant module in `core/` rather than reaching for ZAP/Nuclei/Katana




Installcation How to Run:
-------------------------------
1- Install GoLang -- https://go.dev/dl/

2. install Katana in  VS code terminal --  go install github.com/projectdiscovery/katana/cmd/katana@latest
katana -version   # sanity check

3- Install  Nuclei in VS code termional -- go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -version

4- Run docker Image --- docker pull zaproxy/zap-stable

After Everything god install Run Below Command in Vs Code:
npm run scan -- https://preview.owasp-juice.shop/ 
directly; the goal is that end users never have to.
# Sourav-Repo
