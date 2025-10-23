//! Command-line interface for JSR documentation auditing.
//!
//! This binary provides a CLI tool for analyzing documentation coverage of JSR packages.
//! It can audit packages from the JSR registry, local directories, or pre-generated doc-node files.
//!
//! ## Usage
//!
//! ```bash
//! # Audit a package from JSR registry
//! jsr-doc-audit @scope/package@version
//!
//! # Audit a local package directory
//! jsr-doc-audit --local-path ./my-package
//!
//! # Audit from pre-generated doc-nodes JSON
//! jsr-doc-audit --doc-nodes ./raw.json
//! ```

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use audit_script::{
    analyze_doc_nodes,
    generate_doc_nodes_from_files,
    generate_doc_nodes_from_local_path,
    types::{PackageSpec, format_specifier},
    DocNodesByUrl, DocumentationCoverage,
};
use clap::Parser;
use indexmap::IndexMap;
use log::{debug, info};
use owo_colors::OwoColorize;
use reqwest::blocking::Client;
use serde::Deserialize;
use url::Url;

/// HTTP request timeout in seconds
const HTTP_TIMEOUT_SECS: u64 = 30;

/// Width of the progress bar in characters
const PROGRESS_BAR_WIDTH: usize = 30;

#[derive(Debug, Parser)]
#[command(
    name = "jsr-doc-audit",
    version,
    about = "Audit documentation coverage for a JSR package",
    disable_version_flag = false
)]
struct Cli {
    /// Path to a local raw doc-nodes JSON file (as produced by JSR)
    #[arg(long, value_name = "FILE", conflicts_with = "package")]
    doc_nodes: Option<PathBuf>,

    /// JSR package spec, e.g. @scope/name@1.2.3 (version optional)
    #[arg(
        value_name = "@scope/name[@version]",
        required_unless_present_any = ["doc_nodes", "local_path"]
    )]
    package: Option<String>,

    /// Path to a local JSR package directory (must contain deno.json)
    #[arg(long, value_name = "PATH", conflicts_with_all = ["package", "doc_nodes"])]
    local_path: Option<PathBuf>,

    /// Override the JSR API root (default: https://jsr.io/api)
    #[arg(
        long,
        value_name = "URL",
        env = "JSR_API_ROOT",
        default_value = "https://jsr.io/api"
    )]
    api_root: String,

    /// Override the docs origin that hosts raw doc-node JSON (default: https://docs.jsr.io)
    #[arg(
        long,
        value_name = "URL",
        env = "JSR_DOCS_ORIGIN",
        default_value = "https://docs.jsr.io"
    )]
    docs_origin: String,

    /// Optionally write the generated raw doc-nodes JSON to a file
    #[arg(long, value_name = "FILE")]
    write_raw: Option<PathBuf>,

    /// Enable detailed debug output exploring all doc nodes structure
    #[arg(long)]
    debug_explore: bool,

    /// Enable verbose logging (can also use RUST_LOG=debug)
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    // Initialize logger
    env_logger::Builder::from_default_env()
        .filter_level(if args.verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        .init();

    info!("Starting JSR documentation audit");
    debug!("API root: {}", args.api_root);
    debug!("Docs origin: {}", args.docs_origin);

    let endpoints = Endpoints::new(&args.api_root, &args.docs_origin)?;
    let client = Client::builder()
        .user_agent(format!("jsr-doc-audit/{}", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build()?;

    let (doc_nodes, resolved_spec) = if let Some(path) = args.doc_nodes {
        info!("Loading doc-nodes from file: {}", path.display());
        let json = fs::read_to_string(&path)
            .with_context(|| format!("failed to read doc-nodes file at {}", path.display()))?;
        let parsed: DocNodesByUrl = serde_json::from_str(&json)
            .context("failed to parse doc-nodes JSON; ensure you're pointing at a raw.json file")?;
        debug!("Loaded {} module(s) from file", parsed.len());
        (parsed, None)
    } else if let Some(local_path) = args.local_path {
        info!("Loading package from local path: {}", local_path.display());
        let doc_nodes = generate_doc_nodes_from_local_path(&local_path)?;
        debug!("Built doc nodes for {} module(s)", doc_nodes.len());
        (doc_nodes, None)
    } else {
        let spec_str = args.package.as_deref().expect("clap ensures it is present");
        info!("Fetching package: {}", spec_str);
        let spec = PackageSpec::parse(spec_str)?;
        let resolved = resolve_spec(&client, &endpoints, spec)?;
        info!("Resolved to @{}/{}@{}", resolved.scope, resolved.package, resolved.version);
        debug!("Building doc nodes from registry...");
        let doc_nodes = build_doc_nodes_from_registry(&client, &endpoints, &resolved)?;
        debug!("Built doc nodes for {} module(s)", doc_nodes.len());
        (doc_nodes, Some(resolved))
    };

    if args.debug_explore {
        debug_explore_doc_nodes(&doc_nodes);
    }

    let coverage = analyze_doc_nodes(&doc_nodes);

    if let Some(path) = args.write_raw {
        let raw = serde_json::to_string_pretty(&doc_nodes)?;
        fs::write(&path, raw)
            .with_context(|| format!("failed to write doc-nodes to {}", path.display()))?;
    }

    print_report(&coverage, &doc_nodes, resolved_spec.as_ref());

    Ok(())
}

fn resolve_spec(
    client: &Client,
    endpoints: &Endpoints,
    spec: PackageSpec,
) -> anyhow::Result<ResolvedSpec> {
    let scope = spec.scope;
    let package = spec.package;
    let version = if let Some(version) = spec.version {
        version
    } else {
        fetch_latest_version(client, endpoints, &scope, &package)?
    };

    Ok(ResolvedSpec {
        scope,
        package,
        version,
    })
}

fn fetch_latest_version(
    client: &Client,
    _endpoints: &Endpoints,
    scope: &str,
    package: &str,
) -> anyhow::Result<String> {
    debug!("Fetching latest version for @{}/{}", scope, package);
    let url = format!("https://jsr.io/@{}/{}/meta.json", scope, package);
    let response = client
        .get(&url)
        .send()
        .with_context(|| format!("failed to request package metadata from {url}"))?;

    if !response.status().is_success() {
        bail!(
            "failed to resolve latest version for @{scope}/{package}: received HTTP {}",
            response.status()
        );
    }

    let payload: PackageMetadata = response
        .json()
        .context("failed to decode package metadata")?;

    debug!("Latest version: {}", payload.latest);
    Ok(payload.latest)
}

fn build_doc_nodes_from_registry(
    client: &Client,
    endpoints: &Endpoints,
    spec: &ResolvedSpec,
) -> anyhow::Result<DocNodesByUrl> {
    let metadata = fetch_version_metadata(client, endpoints, spec)?;
    let files = fetch_package_files(client, endpoints, spec, &metadata.manifest)?;

    generate_doc_nodes_from_files(
        &spec.scope,
        &spec.package,
        &spec.version,
        &metadata.exports,
        &IndexMap::new(), // No import map for registry packages
        &files,
    )
}

fn debug_explore_doc_nodes(doc_nodes: &DocNodesByUrl) {
    use log::debug;

    debug!("========== DEBUG EXPLORATION ==========");
    debug!("Total modules: {}", doc_nodes.len());

    for (specifier, nodes) in doc_nodes.iter() {
        debug!("Module: {}", specifier);
        debug!("  Nodes: {}", nodes.len());

        for node in nodes {
            debug!("  - {} ({:?})", node.get_name(), node.def);
            debug!("    JSDoc empty: {}", node.js_doc.is_empty());
            debug!("    Declaration: {:?}", node.declaration_kind);
        }
    }

    debug!("=======================================");
}

fn print_report(
    coverage: &DocumentationCoverage,
    doc_nodes: &DocNodesByUrl,
    spec: Option<&ResolvedSpec>,
) {
    println!("{}", "JSR Documentation Audit".bold().bright_blue());

    if let Some(spec) = spec {
        println!(
            "  Package : {}",
            format!("@{}/{}", spec.scope, spec.package).bold()
        );
        println!("  Version : {}", spec.version.as_str().bold());
    }
    println!("  Modules : {}", doc_nodes.len());

    let fraction = coverage.fraction_documented();
    let pct = coverage.percentage_documented();
    let progress = progress_bar(fraction, PROGRESS_BAR_WIDTH);
    let pct_display = format!("{pct}%");
    let pct_colored = match pct {
        90..=100 => pct_display.green().bold().to_string(),
        70..=89 => pct_display.yellow().bold().to_string(),
        _ => pct_display.red().bold().to_string(),
    };

    println!(
        "  Coverage: {} {} ({} documented / {} total)",
        progress, pct_colored, coverage.documented_symbols, coverage.total_symbols
    );

    if coverage.total_symbols == 0 {
        println!(
            "\n{}",
            "No public exports were detected for this package.".italic()
        );
        return;
    }

    if !coverage.documented_symbol_details.is_empty() {
        let table_rows = coverage
            .documented_symbol_details
            .iter()
            .map(|symbol| {
                build_symbol_row(
                    &symbol.specifier,
                    &symbol.name,
                    &symbol.kind,
                    symbol.declaration_kind.as_ref(),
                    symbol.location.as_ref(),
                )
            })
            .collect();

        print_symbol_table(
            format!(
                "{} ({})",
                "Documented symbols".bold().green(),
                coverage.documented_symbol_details.len()
            ),
            table_rows,
        );
    }

    if coverage.undocumented_symbols.is_empty() {
        println!(
            "\n{}",
            "Every exported symbol is documented. Great job!"
                .green()
                .bold()
        );
        return;
    }

    let table_rows = coverage
        .undocumented_symbols
        .iter()
        .map(|symbol| {
            build_symbol_row(
                &symbol.specifier,
                &symbol.name,
                &symbol.kind,
                symbol.declaration_kind.as_ref(),
                symbol.location.as_ref(),
            )
        })
        .collect();

    print_symbol_table(
        format!(
            "{} ({})",
            "Undocumented symbols".bold().red(),
            coverage.undocumented_symbols.len()
        ),
        table_rows,
    );
}

fn progress_bar(fraction: f32, width: usize) -> String {
    let fraction = fraction.clamp(0.0, 1.0);
    let filled = (fraction * width as f32).round() as usize;
    let filled = filled.min(width);
    let filled_bar = "█".repeat(filled);
    let empty_bar = "░".repeat(width.saturating_sub(filled));
    let bar = format!("[{}{}]", filled_bar, empty_bar);

    if fraction >= 0.9 {
        bar.green().to_string()
    } else if fraction >= 0.7 {
        bar.yellow().to_string()
    } else {
        bar.red().to_string()
    }
}


struct SymbolRow {
    module: String,
    name: String,
    sort_name: String,
    kind: String,
    decl: String,
    location: String,
}

fn build_symbol_row(
    specifier: &Url,
    name: &str,
    kind: &str,
    declaration_kind: Option<&String>,
    location: Option<&audit_script::SymbolLocation>,
) -> SymbolRow {
    let module = format_specifier(specifier);
    let decl = declaration_kind
        .map(|s| s.to_lowercase())
        .filter(|s| s != "public")
        .unwrap_or_default();
    let location = location
        .map(|loc| format!("{}:{}:{}", loc.filename, loc.line, loc.col))
        .unwrap_or_else(|| "?".to_string());

    SymbolRow {
        module,
        name: name.to_string(),
        sort_name: name.to_lowercase(),
        kind: kind.to_string(),
        decl,
        location,
    }
}

fn print_symbol_table(title: String, mut rows: Vec<SymbolRow>) {
    if rows.is_empty() {
        return;
    }

    rows.sort_by(|a, b| {
        let name_cmp = a.sort_name.cmp(&b.sort_name);
        if name_cmp != std::cmp::Ordering::Equal {
            return name_cmp;
        }

        let module_cmp = a.module.cmp(&b.module);
        if module_cmp != std::cmp::Ordering::Equal {
            return module_cmp;
        }

        a.location.cmp(&b.location)
    });

    println!("\n{}", title);

    let header_module = "Module";
    let header_symbol = "Symbol";
    let header_kind = "Kind";
    let header_decl = "Decl";
    let header_location = "Location";

    let mut module_width = header_module.len();
    let mut symbol_width = header_symbol.len();
    let mut kind_width = header_kind.len();
    let mut decl_width = header_decl.len();

    for row in &rows {
        module_width = module_width.max(row.module.len());
        symbol_width = symbol_width.max(row.name.len());
        kind_width = kind_width.max(row.kind.len());
        decl_width = decl_width.max(row.decl.len());
    }

    let header_line = format!(
        "  {:module_width$}  {:symbol_width$}  {:kind_width$}  {:decl_width$}  {}",
        header_module,
        header_symbol,
        header_kind,
        header_decl,
        header_location,
        module_width = module_width,
        symbol_width = symbol_width,
        kind_width = kind_width,
        decl_width = decl_width,
    );
    println!("{}", header_line.bold());

    for row in rows {
        let module_cell = format!(
            "{}",
            format!("{:module_width$}", row.module, module_width = module_width).bright_blue()
        );
        let name_cell = format!(
            "{}",
            format!("{:symbol_width$}", row.name, symbol_width = symbol_width).bold()
        );
        let kind_cell = format!(
            "{}",
            format!("{:kind_width$}", row.kind, kind_width = kind_width).magenta()
        );
        let decl_plain = format!("{:decl_width$}", row.decl, decl_width = decl_width);
        let decl_cell = if row.decl.trim().is_empty() {
            decl_plain
        } else {
            format!("{}", decl_plain.italic().dimmed())
        };
        let location_cell = format!("{}", row.location.cyan());

        println!(
            "  {}  {}  {}  {}  {}",
            module_cell, name_cell, kind_cell, decl_cell, location_cell
        );
    }
}

#[derive(Debug, Clone)]
struct ResolvedSpec {
    scope: String,
    package: String,
    version: String,
}

#[derive(Debug, Clone)]
struct Endpoints {
    #[allow(dead_code)]
    api_root: Url,
    registry_origin: Url,
    #[allow(dead_code)]
    docs_origin: Url,
}

impl Endpoints {
    fn new(api_root: &str, docs_origin: &str) -> anyhow::Result<Self> {
        let api_root = normalize_base_url(api_root).context("invalid API root URL")?;
        let docs_origin = normalize_base_url(docs_origin).context("invalid docs origin URL")?;
        let mut registry_origin = api_root.clone();
        registry_origin.set_path("/");

        Ok(Self {
            api_root,
            registry_origin,
            docs_origin,
        })
    }

    #[allow(dead_code)]
    fn api_url<const N: usize>(&self, segments: [&str; N]) -> anyhow::Result<Url> {
        let mut url = self.api_root.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| anyhow!("API root URL cannot contain query or fragment"))?;
            path.pop_if_empty();
            for segment in segments {
                path.push(segment);
            }
        }
        Ok(url)
    }

    fn version_metadata_url(&self, spec: &ResolvedSpec) -> anyhow::Result<Url> {
        let mut url = self.registry_origin.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| anyhow!("registry origin URL cannot contain query or fragment"))?;
            path.pop_if_empty();
            path.push(&format!("@{}", spec.scope));
            path.push(&spec.package);
            path.push(&format!("{}_meta.json", spec.version));
        }
        Ok(url)
    }

    fn module_url(&self, spec: &ResolvedSpec, module_path: &str) -> anyhow::Result<Url> {
        let mut url = self.registry_origin.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("registry origin URL cannot contain query or fragment"))?;
            segments.pop_if_empty();
            segments.push(&format!("@{}", spec.scope));
            segments.push(&spec.package);
            segments.push(&spec.version);

            let trimmed = module_path.trim_start_matches('/');
            if !trimmed.is_empty() {
                for part in trimmed.split('/') {
                    if !part.is_empty() {
                        segments.push(part);
                    }
                }
            }
        }
        Ok(url)
    }
}

fn normalize_base_url(input: &str) -> anyhow::Result<Url> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("URL cannot be empty");
    }

    let mut normalized = trimmed.trim_end_matches('/').to_string();
    normalized.push('/');
    Url::parse(&normalized).map_err(|err| anyhow!(err))
}

#[derive(Debug, Deserialize)]
struct PackageMetadata {
    latest: String,
}

#[derive(Debug, Deserialize)]
struct VersionMetadata {
    #[serde(default)]
    manifest: HashMap<String, ManifestEntry>,
    #[serde(default)]
    exports: IndexMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct ManifestEntry {
    #[allow(dead_code)]
    size: Option<usize>,
    #[allow(dead_code)]
    checksum: Option<String>,
}

fn fetch_version_metadata(
    client: &Client,
    endpoints: &Endpoints,
    spec: &ResolvedSpec,
) -> anyhow::Result<VersionMetadata> {
    let url = endpoints.version_metadata_url(spec)?;
    let response = client
        .get(url.clone())
        .header("Accept", "application/json")
        .send()
        .with_context(|| format!("failed to download version metadata from {url}"))?;

    if !response.status().is_success() {
        bail!(
            "failed to download version metadata for @{}/{}/{}: received HTTP {}",
            spec.scope,
            spec.package,
            spec.version,
            response.status()
        );
    }

    let metadata = response
        .json::<VersionMetadata>()
        .context("failed to decode version metadata JSON")?;

    if metadata.exports.is_empty() {
        bail!(
            "version metadata for @{}/{}/{} does not contain exports",
            spec.scope,
            spec.package,
            spec.version
        );
    }

    Ok(metadata)
}

fn fetch_package_files(
    client: &Client,
    endpoints: &Endpoints,
    spec: &ResolvedSpec,
    manifest: &HashMap<String, ManifestEntry>,
) -> anyhow::Result<HashMap<String, Vec<u8>>> {
    if manifest.is_empty() {
        bail!(
            "version metadata for @{}/{}/{} does not include a manifest",
            spec.scope,
            spec.package,
            spec.version
        );
    }

    let mut files = HashMap::new();

    for path in manifest.keys() {
        let url = endpoints.module_url(spec, path)?;
        let response = client
            .get(url.clone())
            .header(
                "Accept",
                "application/typescript,application/javascript;q=0.9,text/plain;q=0.5",
            )
            .send()
            .with_context(|| format!("failed to download module from {url}"))?;

        if !response.status().is_success() {
            bail!(
                "failed to download module {} for @{}/{}/{}: received HTTP {}",
                path,
                spec.scope,
                spec.package,
                spec.version,
                response.status()
            );
        }

        let bytes = response
            .bytes()
            .with_context(|| format!("failed to read body for {}", path))?;
        let canonical = format!("/{}", path.trim_start_matches('/'));
        files.insert(canonical, bytes.to_vec());
    }

    Ok(files)
}
