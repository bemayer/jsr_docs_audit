//! WebAssembly bindings for JSR documentation auditing.
//!
//! This module provides JavaScript/TypeScript-compatible bindings for auditing JSR package
//! documentation coverage from the browser or Node.js environments. It exposes the core
//! functionality through WASM, enabling client-side documentation analysis.
//!
//! ## Main Export
//!
//! - `audit_package`: Async function that takes a package specifier (e.g., "@scope/name@version")
//!   and returns detailed coverage statistics and symbol information.

use std::collections::HashMap;
use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use indexmap::IndexMap;
use crate::{analyze_doc_nodes, generate_doc_nodes_from_files, types::{PackageSpec, format_specifier}};

/// Helper to convert Rust errors into JavaScript errors with context.
fn to_js_error(context: &str, err: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&format!("{}: {}", context, err))
}

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();

    #[cfg(target_arch = "wasm32")]
    {
        use log::Level;
        console_log::init_with_level(Level::Debug).expect("error initializing log");
    }
}

/// Result of a package audit, returned to JavaScript.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditResult {
    /// Package identification information.
    pub package: PackageInfo,
    /// Coverage statistics summary.
    pub coverage: CoverageStats,
    /// List of documented symbols.
    pub documented: Vec<SymbolInfo>,
    /// List of undocumented symbols.
    pub undocumented: Vec<SymbolInfo>,
}

/// Package identification information.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageInfo {
    /// JSR scope name (without @ prefix).
    pub scope: String,
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: String,
}

/// Documentation coverage statistics.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageStats {
    /// Total number of public symbols.
    pub total_symbols: usize,
    /// Number of documented symbols.
    pub documented_symbols: usize,
    /// Number of undocumented symbols.
    pub undocumented_symbols: usize,
    /// Coverage percentage (0-100).
    pub percentage: u32,
}

/// Information about a symbol for JavaScript export.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SymbolInfo {
    /// Module path where symbol is defined.
    pub module: String,
    /// Symbol name.
    pub name: String,
    /// Symbol kind (e.g., "function", "class").
    pub kind: String,
    /// Source location (format: "filename:line:col").
    pub location: String,
}

#[wasm_bindgen]
pub async fn audit_package(package_spec: String) -> Result<JsValue, JsValue> {
    log::info!("Auditing package: {}", package_spec);

    // Parse package spec
    let spec = PackageSpec::parse(&package_spec)
        .map_err(|e| to_js_error("Invalid package spec", e))?;

    // Resolve version if not provided
    let version = if let Some(v) = spec.version {
        v
    } else {
        fetch_latest_version(&spec.scope, &spec.package)
            .await
            .map_err(|e| to_js_error("Failed to fetch latest version", e))?
    };

    log::info!("Resolved to @{}/{}@{}", spec.scope, spec.package, version);

    // Fetch package metadata
    let metadata = fetch_version_metadata(&spec.scope, &spec.package, &version)
        .await
        .map_err(|e| to_js_error("Failed to fetch metadata", e))?;

    // Fetch package files
    let files = fetch_package_files(&spec.scope, &spec.package, &version, &metadata.manifest)
        .await
        .map_err(|e| to_js_error("Failed to fetch package files", e))?;

    log::info!("Fetched {} files", files.len());

    // Generate doc nodes
    let doc_nodes = generate_doc_nodes_from_files(
        &spec.scope,
        &spec.package,
        &version,
        &metadata.exports,
        &IndexMap::new(),
        &files,
    )
    .await
    .map_err(|e| to_js_error("Failed to generate doc nodes", e))?;

    log::info!("Generated doc nodes for {} modules", doc_nodes.len());

    // Analyze coverage
    let coverage = analyze_doc_nodes(&doc_nodes);

    // Convert to result format
    let result = convert_to_audit_result(
        &spec.scope,
        &spec.package,
        &version,
        &coverage,
    );

    // Serialize to JsValue
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| to_js_error("Failed to serialize result", e))
}

/// Convert a symbol location to a string representation.
fn format_location(location: Option<&crate::SymbolLocation>) -> String {
    location
        .map(|loc| format!("{}:{}:{}", loc.filename, loc.line, loc.col))
        .unwrap_or_else(|| "?".to_string())
}

/// Convert a coverage symbol to a SymbolInfo for WASM export.
fn convert_symbol<T>(sym: &T) -> SymbolInfo
where
    T: SymbolInfoSource,
{
    SymbolInfo {
        module: format_specifier(&sym.specifier()),
        name: sym.name().to_string(),
        kind: sym.kind().to_string(),
        location: format_location(sym.location()),
    }
}

/// Trait to extract common symbol information from different symbol types.
trait SymbolInfoSource {
    fn specifier(&self) -> &url::Url;
    fn name(&self) -> &str;
    fn kind(&self) -> &str;
    fn location(&self) -> Option<&crate::SymbolLocation>;
}

impl SymbolInfoSource for crate::DocumentedSymbol {
    fn specifier(&self) -> &url::Url {
        &self.specifier
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &str {
        &self.kind
    }
    fn location(&self) -> Option<&crate::SymbolLocation> {
        self.location.as_ref()
    }
}

impl SymbolInfoSource for crate::UndocumentedSymbol {
    fn specifier(&self) -> &url::Url {
        &self.specifier
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &str {
        &self.kind
    }
    fn location(&self) -> Option<&crate::SymbolLocation> {
        self.location.as_ref()
    }
}

fn convert_to_audit_result(
    scope: &str,
    package: &str,
    version: &str,
    coverage: &crate::DocumentationCoverage,
) -> AuditResult {
    let documented = coverage
        .documented_symbol_details
        .iter()
        .map(convert_symbol)
        .collect();

    let undocumented = coverage
        .undocumented_symbols
        .iter()
        .map(convert_symbol)
        .collect();

    AuditResult {
        package: PackageInfo {
            scope: scope.to_string(),
            name: package.to_string(),
            version: version.to_string(),
        },
        coverage: CoverageStats {
            total_symbols: coverage.total_symbols,
            documented_symbols: coverage.documented_symbols,
            undocumented_symbols: coverage.undocumented_symbols.len(),
            percentage: coverage.percentage_documented(),
        },
        documented,
        undocumented,
    }
}

#[derive(Deserialize)]
struct PackageMetadata {
    latest: String,
}

async fn fetch_latest_version(scope: &str, package: &str) -> Result<String, String> {
    let url = format!("https://jsr.io/@{}/{}/meta.json", scope, package);

    log::debug!("Fetching package metadata from: {}", url);

    let response = reqwest::get(&url)
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Failed to fetch package metadata: HTTP {}",
            response.status()
        ));
    }

    let data: PackageMetadata = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    Ok(data.latest)
}

#[derive(Deserialize)]
struct VersionMetadata {
    #[serde(default)]
    manifest: HashMap<String, ManifestEntry>,
    #[serde(default)]
    exports: IndexMap<String, String>,
}

#[derive(Deserialize)]
struct ManifestEntry {
    #[allow(dead_code)]
    size: Option<usize>,
    #[allow(dead_code)]
    checksum: Option<String>,
}

async fn fetch_version_metadata(
    scope: &str,
    package: &str,
    version: &str,
) -> Result<VersionMetadata, String> {
    let url = format!("https://jsr.io/@{}/{}/{}_meta.json", scope, package, version);

    log::debug!("Fetching metadata from: {}", url);

    let response = reqwest::get(&url)
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Failed to fetch metadata: HTTP {}", response.status()));
    }

    let metadata: VersionMetadata = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse metadata: {}", e))?;

    if metadata.exports.is_empty() {
        return Err("Package has no exports".to_string());
    }

    Ok(metadata)
}

async fn fetch_package_files(
    scope: &str,
    package: &str,
    version: &str,
    manifest: &HashMap<String, ManifestEntry>,
) -> Result<HashMap<String, Vec<u8>>, String> {
    if manifest.is_empty() {
        return Err("Manifest is empty".to_string());
    }

    log::info!("Fetching {} files in parallel...", manifest.len());

    // Create a vector of futures for all file fetches
    let fetch_futures: Vec<_> = manifest
        .keys()
        .map(|path| {
            let scope = scope.to_string();
            let package = package.to_string();
            let version = version.to_string();
            let path = path.clone();

            async move {
                let url = format!(
                    "https://jsr.io/@{}/{}/{}/{}",
                    scope,
                    package,
                    version,
                    path.trim_start_matches('/')
                );

                log::debug!("Fetching file: {}", url);

                let response = reqwest::get(&url)
                    .await
                    .map_err(|e| format!("Failed to fetch {}: {}", path, e))?;

                if !response.status().is_success() {
                    return Err(format!("Failed to fetch {}: HTTP {}", path, response.status()));
                }

                let bytes = response
                    .bytes()
                    .await
                    .map_err(|e| format!("Failed to read {}: {}", path, e))?;

                let canonical = format!("/{}", path.trim_start_matches('/'));
                Ok::<(String, Vec<u8>), String>((canonical, bytes.to_vec()))
            }
        })
        .collect();

    // Wait for all fetches to complete
    use futures::future::join_all;
    let results = join_all(fetch_futures).await;

    // Collect results into HashMap
    let mut files = HashMap::new();
    for result in results {
        let (path, bytes) = result?;
        files.insert(path, bytes);
    }

    log::info!("Successfully fetched all {} files", files.len());

    Ok(files)
}
