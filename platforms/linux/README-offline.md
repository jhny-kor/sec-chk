# KODA Linux Offline Distribution

This folder is the Linux distribution layer for KODA. It does not fork scanner
logic. Source installs and packages copy the shared Python engine from
`platforms/shared/python/security_scanner/` into the Linux bundle.

## Install From Source

```bash
cd /path/to/koda
bash platforms/linux/install.sh
~/.local/bin/koda list-categories
```

Use a custom install location when the server account has a managed application
directory:

```bash
KODA_PREFIX=/opt/koda KODA_BIN_DIR=/usr/local/bin bash platforms/linux/install.sh
```

## Web Dashboard

Start the dashboard for another workstation on the closed network:

```bash
koda serve --host 0.0.0.0 --port 8765
```

Then open:

```text
http://<server-ip>:8765/security-dashboard.html
```

Use `koda serve` without `--host` for same-server loopback access only.

The installer and package include the Playwright Chromium renderer. Confirm the
server is healthy before handing the dashboard to an operator:

```bash
curl --fail http://127.0.0.1:8765/api/health
```

After a completed scan, **보고서 → PDF** downloads a PDF file directly; it does
not open a print dialog. Do not omit Chromium when building an offline bundle:
`install.sh` and `package.sh` fail if the renderer cannot be staged.

## Build An Offline Tarball

Build on a connected machine, then move the tarball into the closed network.

```bash
bash platforms/linux/package.sh
```

Install on the target Linux server:

```bash
tar -xzf koda-linux-x86_64-0.1.0.tar.gz
cd koda-linux-x86_64-0.1.0
bash install.sh
koda scan --target /deploy/app --format json --output reports/koda.json --fail-on high
```

## Deployment Gate

KODA exits with status `1` when `--fail-on` finds a matching severity. Put that
command before deployment promotion:

```bash
koda scan --target "$DEPLOY_DIR" --format json --output reports/koda-security.json --fail-on high
```

For scan plus deployment-shape evidence in one command:

```bash
koda deploy-check --target "$DEPLOY_DIR" --output-dir reports/koda-deploy --fail-on high
```

To verify that the deployed files match an approved shape:

```bash
koda manifest create --target /deploy/package --output reports/approved-manifest.json
koda manifest compare --baseline reports/approved-manifest.json --target /app/current --output reports/manifest-compare.json
```

For a full example, see `examples/deploy-gate.sh`.

## GitLab CI

Use `examples/gitlab-ci.yml` as a starter job. It installs KODA locally in the
job workspace, scans only merge-request changes when a target branch is
available, writes a full HTML report, and writes `reports/koda-host.json` for
the runner host posture.

Set `KODA_DEPLOY_DIR` when the job also has access to a staged deployment
directory and should run `koda deploy-check`.

## Closed-Network Defaults

- Default scans are local and offline.
- Do not enable `--enable-osv` or `--enable-vuln-intel` in a closed network
  unless those services are routed to an approved internal mirror.
- Keep shared scanner changes in `platforms/shared/python/security_scanner/`;
  keep Linux install, packaging, and deployment scripts in `platforms/linux/`.
