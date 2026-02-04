# Release Checklist

Use this checklist before publishing to npm.

## 1) Versioning

1. Pick a version (SemVer).
2. Update `version` in each package:
   - `packages/openclaw/package.json`
   - `packages/cli/package.json`
   - `packages/core/package.json`
   - `packages/redaction/package.json`
   - `packages/scanner/package.json`
3. Update internal dependency pins to the same version:
   - `@mindaiproject/firewall-core`
   - `@mindaiproject/firewall-redaction`
   - `@mindaiproject/firewall-scanner`
   - `@mindaiproject/openclaw-tool-firewall`

## 2) Preflight checks

1. Run tests:

```bash
npm test
```

2. Build + bundle:

```bash
npm run build
npm run bundle
```

3. Audit dependencies:

```bash
npm audit
```

## 3) Clean install smoke test

1. In a clean directory:

```bash
npm pack ./packages/openclaw
```

2. Install the tarball in a temp folder and load it in OpenClaw.

## 4) OpenClaw smoke test

1. Enable the plugin:

```bash
openclaw plugins enable openclaw-tool-firewall
```

2. Create policy:

```bash
openclaw firewall init --preset standard
```

If `openclaw firewall` is missing, use `mindai-firewall init --preset standard`.

3. Trigger a known tool call (e.g., `read`) and verify:
   - decisions are logged
   - approvals are prompted for write/critical tools
   - output redaction and injection scanning work

## 5) Docs and policy review

1. Confirm docs are up to date:
   - `docs/quickstart.md`
   - `docs/installation.md`
   - `docs/policies.md`
   - `docs/threat-model.md`
   - `docs/why-firewall.md`
   - `docs/examples.md`

2. Re-run the audit:

```bash
openclaw firewall audit
```

If `openclaw firewall` is missing, use `mindai-firewall audit`.
