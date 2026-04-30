# sh

A collection of single-purpose shell scripts. Each one is self-contained, safe to inspect, and runnable via a single `curl | bash` line.

## Scripts

| Script | Purpose | Docs |
|--------|---------|------|
| [`mitigate-copyfail.sh`](mitigate-copyfail.sh) | Mitigate CVE-2026-31431 ("Copy Fail") — disables the vulnerable `algif_aead` Linux kernel module until you can install a patched kernel. | [docs](mitigate-copyfail.md) |

## Running a script

Every script in this repo can be executed with one line:

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/sh/main/<script-name>.sh | sudo bash
```

To pass arguments through the pipe, use `bash -s --`:

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/sh/main/<script-name>.sh | sudo bash -s -- --check
```

If you'd rather inspect before you run (sensible for anything that asks for root):

```bash
curl -fsSL https://raw.githubusercontent.com/ersinkoc/sh/main/<script-name>.sh -o <script-name>.sh
less <script-name>.sh
sudo bash <script-name>.sh
```

See each script's linked docs for flags, exit codes, and per-host notes.

## Conventions

- Pure POSIX-ish bash, no extra runtime dependencies beyond standard utilities (`grep`, `awk`, `sed`, `lsof` where needed).
- `set -euo pipefail` everywhere. Scripts fail loudly, never silently.
- Three-mode pattern where applicable: default = apply, `--check` = read-only status, `--revert` = undo.
- Exit codes are meaningful and documented in each script's docs.
- Color output when stdout is a TTY, plain text in pipes/CI.

## License

MIT.
