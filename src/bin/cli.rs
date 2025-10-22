use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use audit_script::{
    analyze_doc_nodes, generate_doc_nodes_from_files, DocNodesByUrl, DocumentationCoverage,
};
use clap::Parser;
use indexmap::IndexMap;
use owo_colors::OwoColorize;
use reqwest::blocking::Client;
use serde::Deserialize;
use url::Url;

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
        required_unless_present = "doc_nodes"
    )]
    package: Option<String>,

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
}

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    let endpoints = Endpoints::new(&args.api_root, &args.docs_origin)?;
    let client = Client::builder()
        .user_agent(format!("jsr-doc-audit/{}", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .build()?;

    let (doc_nodes, resolved_spec) = if let Some(path) = args.doc_nodes {
        let json = fs::read_to_string(&path)
            .with_context(|| format!("failed to read doc-nodes file at {}", path.display()))?;
        let parsed: DocNodesByUrl = serde_json::from_str(&json)
            .context("failed to parse doc-nodes JSON; ensure you're pointing at a raw.json file")?;
        (parsed, None)
    } else {
        let spec_str = args.package.as_deref().expect("clap ensures it is present");
        let spec = PackageSpec::parse(spec_str)?;
        let resolved = resolve_spec(&client, &endpoints, spec)?;
        let doc_nodes = build_doc_nodes_from_registry(&client, &endpoints, &resolved)?;
        (doc_nodes, Some(resolved))
    };

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
    endpoints: &Endpoints,
    scope: &str,
    package: &str,
) -> anyhow::Result<String> {
    let url = endpoints.api_url(["scopes", scope, "packages", package, "versions", "latest"])?;
    let response = client
        .get(url.clone())
        .send()
        .with_context(|| format!("failed to request latest version from {url}"))?;

    if !response.status().is_success() {
        bail!(
            "failed to resolve latest version for @{scope}/{package}: received HTTP {}",
            response.status()
        );
    }

    let payload: LatestVersionResponse = response
        .json()
        .context("failed to decode version response")?;

    Ok(payload.version)
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
        &files,
    )
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
    let progress = progress_bar(fraction, 30);
    let pct_display = format!("{pct}%");
    let pct_colored = match pct {
        90..=100 => format!("{}", pct_display.clone().green().bold()),
        70..=89 => format!("{}", pct_display.clone().yellow().bold()),
        _ => format!("{}", pct_display.clone().red().bold()),
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

fn format_specifier(specifier: &url::Url) -> String {
    let path = specifier.path().trim_start_matches('/');
    if path.is_empty() {
        specifier.to_string()
    } else {
        path.to_string()
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
struct PackageSpec {
    scope: String,
    package: String,
    version: Option<String>,
}

impl PackageSpec {
    fn parse(input: &str) -> anyhow::Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            bail!("package specifier cannot be empty");
        }

        let without_at = trimmed.strip_prefix('@').unwrap_or(trimmed);
        let (scope, rest) = without_at
            .split_once('/')
            .ok_or_else(|| anyhow!("package specifier must be in the form scope/name"))?;

        if scope.is_empty() {
            bail!("scope cannot be empty");
        }

        let (package, version) = if let Some((pkg, ver)) = rest.split_once('@') {
            (pkg, Some(ver))
        } else if let Some((pkg, ver)) = rest.split_once('/') {
            (pkg, Some(ver))
        } else {
            (rest, None)
        };

        if package.is_empty() {
            bail!("package name cannot be empty");
        }

        let version = version.filter(|v| !v.is_empty()).map(str::to_string);

        Ok(Self {
            scope: scope.to_string(),
            package: package.to_string(),
            version,
        })
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
    api_root: Url,
    registry_origin: Url,
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

    #[allow(dead_code)]
    fn docs_url(&self, spec: &ResolvedSpec) -> anyhow::Result<Url> {
        let mut url = self.docs_origin.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| anyhow!("docs origin URL cannot contain query or fragment"))?;
            path.pop_if_empty();
            path.push(&format!("@{}", spec.scope));
            path.push(&spec.package);
            path.push(&spec.version);
            path.push("raw.json");
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
struct LatestVersionResponse {
    version: String,
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
