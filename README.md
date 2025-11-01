# JSR Documentation Audit

Analyze documentation coverage for JSR packages, both via CLI and web interface powered by WebAssembly.

## 🌐 Web Interface

**[JSR Docs Audit](https://bemayer.github.io/jsr_docs_audit/)**

Features:
- 🔍 Search JSR package
- 📊 Instant documentation coverage analysis
- 📝 Detailed symbol-level reporting
- ⚡ Runs entirely in your browser via WebAssembly

## CLI usage

```powershell
cargo run -p audit_script -- @scope/name[@version]
```

- Pass `@scope/name` to inspect the latest unyanked version.
- Append `@version` to pin a specific release (for example
  `@bemayer/rubique@1.0.4`).
- Use `--doc-nodes <FILE>` to analyse a local `raw.json` export without touching
  the network.
- Use `--local-path <PATH>` to analyse a local JSR package directory:
  ```powershell
  cargo run -p audit_script -- --local-path ../Rubique
  ```

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

## 🔧 Building the Web Interface

### Prerequisites

- Rust (with `wasm32-unknown-unknown` target)
- wasm-pack

```bash
# Install wasm32 target
rustup target add wasm32-unknown-unknown

# Install wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

### Build

```bash
# Build everything
./build.sh

# Or manually
wasm-pack build --target web --out-dir dist/pkg --no-default-features --release
```

### Local Testing

```bash
python3 -m http.server 8000 --directory dist
```

Then open http://localhost:8000

## Development

```bash
# Format code
cargo fmt

# Check compilation
cargo check

# Build CLI
cargo build --features cli

# Build WASM
cargo build --target wasm32-unknown-unknown --no-default-features

# Run CLI
cargo run --features cli -- --help
```

## 📁 Project Structure

```
jsr_docs_audit/
├── src/
│   ├── lib.rs          # Core analysis logic
│   ├── wasm.rs         # WASM bindings
│   └── bin/
│       └── cli.rs      # CLI application
├── dist/
│   ├── index.html      # Web interface
│   ├── style.css       # Styling
│   ├── app.js          # JavaScript app
│   └── pkg/            # Built WASM (generated)
├── .github/
│   └── workflows/
│       └── deploy.yml  # CI/CD pipeline
├── build.sh            # Build script
└── Cargo.toml
```

## 📜 License

MIT
