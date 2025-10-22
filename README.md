# JSR Documentation Audit

A standalone Rust crate that mirrors the JSR registry's documentation analysis
so you can audit documentation coverage for any published package.

## CLI usage

```powershell
cargo run -p audit_script -- @scope/name[@version]
```

- Pass `@scope/name` to inspect the latest unyanked version.
- Append `@version` to pin a specific release (for example
  `@bemayer/rubique@1.0.4`).
- Use `--doc-nodes <FILE>` to analyse a local `raw.json` export without touching
  the network.

The CLI automatically fetches doc nodes from the public docs bucket. If your
environment requires a different origin, override it with either the flag or the
environment variable:

```powershell
$env:JSR_DOCS_ORIGIN = "https://docs.jsr.io"
cargo run -p audit_script -- @bemayer/rubique
```

Other helpful flags:

- `--api-root <URL>` / `JSR_API_ROOT` &mdash; point at an alternate registry
  API.
- `--docs-origin <URL>` / `JSR_DOCS_ORIGIN` &mdash; customise the doc-nodes
  host.

## Output preview

The CLI prints a coloured summary with a progress bar and neatly aligned tables
of undocumented symbols. Example (trimmed):

```
JSR Documentation Audit
  Package : @scope/name
  Version : 1.0.4
  Modules : 5
  Coverage: [██████████░░░░░░░░░░░░░░] 68% (34 documented / 50 total)

Undocumented symbols (3)
  Module            Symbol      Kind       Location
  mod.ts            doThing     function   src/mod.ts:42:1
  another.ts        helper      function   src/another.ts:17:5
```

## Development

```powershell
cargo fmt -p audit_script
cargo check -p audit_script
```

Run `cargo run -p audit_script -- --help` to see the full option list.
