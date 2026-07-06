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
