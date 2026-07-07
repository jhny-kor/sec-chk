# KODA Linux Install

Linux uses the shared Python engine from `platforms/shared/python/` and the Linux wrapper in `platforms/linux/`. It is designed for closed-network servers and does not require administrator privileges when installed under a user-owned prefix.

## Run From Source

```bash
cd /path/to/koda
PYTHONPATH=platforms/shared/python python3 -m security_scanner list-categories
PYTHONPATH=platforms/shared/python python3 -m security_scanner host-scan --format json --min-severity info
```

## Install From Source

```bash
cd /path/to/koda
bash platforms/linux/install.sh
~/.local/bin/koda list-categories
~/.local/bin/koda host-scan --format json
```

For a managed server location:

```bash
bash platforms/linux/install.sh --prefix /opt/koda --bin-dir /usr/local/bin
koda scan --target /deploy/app --format json --fail-on high
koda host-scan --format json --min-severity info
```

## GitLab Runner

Use `platforms/linux/examples/gitlab-ci.yml` as the starter job for closed-network GitLab Runner setups. It installs KODA into the job workspace, runs changed-file scanning for merge requests, writes a full HTML report, and always writes a Linux host posture report:

```yaml
include:
  - local: platforms/linux/examples/gitlab-ci.yml
```

Set these variables as needed:

| Variable | Default | Use |
| --- | --- | --- |
| `KODA_FAIL_ON` | `high` | Merge/deploy gate severity. |
| `KODA_TARGET` | `$CI_PROJECT_DIR` | Source directory to scan. |
| `KODA_DEPLOY_DIR` | unset | Optional deployed artifact directory for `deploy-check`. |

For merge request diff scanning, keep enough Git history for the target branch. In GitLab this usually means setting `GIT_DEPTH: "0"` on the job or runner.

## Deployment Gate

For server promotion, run:

```bash
DEPLOY_DIR=/deploy/app KODA_REPORT_DIR=reports/koda bash platforms/linux/examples/deploy-gate.sh
```

The script writes:

- `koda-host.json`
- `koda-deploy-scan.json`
- `koda-deploy-manifest.json`
- `koda-security.html`

## Build Offline Package

Build on a connected machine:

```bash
bash platforms/linux/package.sh
```

Move the generated `dist/linux/koda-linux-x86_64-*.tar.gz` file to the target server, then install:

```bash
tar -xzf koda-linux-x86_64-*.tar.gz
cd koda-linux-x86_64-*
bash install.sh
koda list-categories
```

## Notes

- Default scans are local and offline.
- Use `--enable-osv` or `--enable-vuln-intel` only when the server can reach approved vulnerability feeds or internal mirrors.
- Linux-specific wrapper, installer, package, and CI examples live in `platforms/linux/`.
