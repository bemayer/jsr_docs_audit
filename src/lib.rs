//! JSR Documentation Audit Library
//!
//! This library provides tools for analyzing documentation coverage of JSR (JavaScript Registry) packages.
//! It generates documentation nodes from TypeScript/JavaScript source files and calculates coverage statistics
//! based on the presence of JSDoc comments on public exports.
//!
//! ## Features
//!
//! - Parse and analyze JSR package documentation
//! - Generate documentation nodes from local directories or in-memory files
//! - Calculate documentation coverage percentages
//! - Support for both native (CLI) and WASM (web) targets
//! - Parallel async operations for efficient processing

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use deno_ast::{MediaType, ModuleSpecifier, ParsedSource};
use deno_doc::node::DeclarationKind;
use deno_doc::{DocNode, DocNodeDef};
use deno_error::JsErrorBox;
use log::{debug, info};
use deno_graph::analysis::ModuleInfo;
use deno_graph::ast::{CapturingModuleAnalyzer, DefaultEsParser, ParseOptions};
use deno_graph::source::{
    JsrUrlProvider, LoadError, LoadFuture, LoadOptions, LoadResponse, LoadResult, Loader,
    ResolveError, Resolver, load_data_url,
};
use deno_graph::{BuildOptions, GraphKind, ModuleGraph, WorkspaceMember, resolve_import};
use deno_graph::packages::JsrVersionResolver;
use std::borrow::Cow;
use deno_semver::{StackString, Version, jsr::JsrPackageReqReference};
use futures::FutureExt;
use indexmap::IndexMap;
use url::Url;

#[cfg(not(target_arch = "wasm32"))]
use tokio::runtime::Builder as TokioRuntimeBuilder;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub mod types;

/// Mapping of module specifiers to the DocNodes extracted from that module.
pub type DocNodesByUrl = IndexMap<ModuleSpecifier, Vec<DocNode>>;

/// Summary of documentation coverage for a package.
#[derive(Debug, Clone, PartialEq)]
pub struct DocumentationCoverage {
    /// Total number of public symbols analyzed.
    pub total_symbols: usize,
    /// Number of symbols with JSDoc documentation.
    pub documented_symbols: usize,
    /// Detailed information about documented symbols.
    pub documented_symbol_details: Vec<DocumentedSymbol>,
    /// Detailed information about undocumented symbols.
    pub undocumented_symbols: Vec<UndocumentedSymbol>,
}

/// Representation of an undocumented exported symbol for reporting purposes.
#[derive(Debug, Clone, PartialEq)]
pub struct UndocumentedSymbol {
    /// Module URL where the symbol is defined.
    pub specifier: ModuleSpecifier,
    /// Name of the symbol.
    pub name: String,
    /// Kind of symbol (e.g., "function", "class", "variable").
    pub kind: String,
    /// Declaration kind (e.g., "export", "default").
    pub declaration_kind: Option<String>,
    /// Source code location of the symbol.
    pub location: Option<SymbolLocation>,
}

/// Representation of a documented exported symbol for reporting purposes.
#[derive(Debug, Clone, PartialEq)]
pub struct DocumentedSymbol {
    /// Module URL where the symbol is defined.
    pub specifier: ModuleSpecifier,
    /// Name of the symbol.
    pub name: String,
    /// Kind of symbol (e.g., "function", "class", "variable").
    pub kind: String,
    /// Declaration kind (e.g., "export", "default").
    pub declaration_kind: Option<String>,
    /// Source code location of the symbol.
    pub location: Option<SymbolLocation>,
}

/// Source code location information for a symbol.
#[derive(Debug, Clone, PartialEq)]
pub struct SymbolLocation {
    /// Source file path.
    pub filename: String,
    /// Line number (1-indexed).
    pub line: u32,
    /// Column number (1-indexed).
    pub col: u32,
}

impl DocumentationCoverage {
    /// Return the documentation coverage as a float in the range 0.0..=1.0.
    pub fn fraction_documented(&self) -> f32 {
        if self.total_symbols == 0 {
            return 1.0;
        }
        self.documented_symbols as f32 / self.total_symbols as f32
    }

    /// Return the documentation coverage percentage (0-100).
    pub fn percentage_documented(&self) -> u32 {
        (self.fraction_documented() * 100.0).round() as u32
    }
}

/// Compute documentation coverage and collect undocumented symbols from the
/// provided doc nodes. Mirrors the server-side logic used in JSR.
pub fn analyze_doc_nodes(doc_nodes: &DocNodesByUrl) -> DocumentationCoverage {
    let mut total_symbols = 0usize;
    let mut documented_symbols = 0usize;
    let mut documented_symbol_details = Vec::new();
    let mut undocumented_symbols = Vec::new();

    info!("Analyzing {} module(s)", doc_nodes.len());

    for (specifier, nodes) in doc_nodes.iter() {
        debug!("Module: {}", specifier);
        debug!("  Total nodes in this module: {}", nodes.len());

        for node in nodes {
            let node_name = node.get_name();
            let node_kind = format_doc_node_kind(&node.def);
            let node_decl_kind = format!("{:#?}", node.declaration_kind);

            debug!("  → Node: '{}' (kind: {}, decl: {})", node_name, node_kind, node_decl_kind);
            debug!("    Location: {}:{}:{}", node.location.filename, node.location.line, node.location.col);

            if matches!(node.def, DocNodeDef::ModuleDoc | DocNodeDef::Import { .. }) {
                debug!("    ⏭️  SKIPPED: ModuleDoc or Import (not counted in coverage)");
                continue;
            }

            if node.declaration_kind == DeclarationKind::Private {
                debug!("    ⏭️  SKIPPED: Private declaration (not counted in coverage)");
                continue;
            }

            total_symbols += 1;

            debug!("    JSDoc is_empty: {}", node.js_doc.is_empty());

            if !node.js_doc.is_empty() {
                debug!("    JSDoc content:");
                if let Some(doc) = &node.js_doc.doc {
                    debug!("      - doc: {:?}", doc);
                }
                debug!("      - tags count: {}", node.js_doc.tags.len());
                for (i, tag) in node.js_doc.tags.iter().enumerate() {
                    debug!("      - tag[{}]: {:?}", i, tag);
                }
                debug!("    ✅ DOCUMENTED");
                documented_symbols += 1;
                documented_symbol_details.push(DocumentedSymbol {
                    specifier: specifier.clone(),
                    name: node.get_name().to_string(),
                    kind: format_doc_node_kind(&node.def),
                    declaration_kind: Some(format!("{:#?}", node.declaration_kind)),
                    location: Some(SymbolLocation {
                        filename: node.location.filename.to_string(),
                        line: node.location.line as u32,
                        col: node.location.col as u32,
                    }),
                });
            } else {
                debug!("    ❌ NO JSDoc found for this symbol!");
                debug!("    ➡️  UNDOCUMENTED");
                undocumented_symbols.push(UndocumentedSymbol {
                    specifier: specifier.clone(),
                    name: node.get_name().to_string(),
                    kind: format_doc_node_kind(&node.def),
                    declaration_kind: Some(format!("{:#?}", node.declaration_kind)),
                    location: Some(SymbolLocation {
                        filename: node.location.filename.to_string(),
                        line: node.location.line as u32,
                        col: node.location.col as u32,
                    }),
                });
            }
        }
    }

    // If there are no symbols, consider the package fully documented, matching
    // the behavior in the JSR backend.
    if total_symbols == 0 {
        documented_symbols = 0;
    }

    info!("========== SUMMARY ==========");
    info!("Total symbols analyzed: {}", total_symbols);
    info!("Documented symbols: {}", documented_symbols);
    info!("Undocumented symbols: {}", undocumented_symbols.len());
    info!("Coverage: {:.1}%", if total_symbols > 0 { (documented_symbols as f32 / total_symbols as f32) * 100.0 } else { 100.0 });
    info!("=============================");

    DocumentationCoverage {
        total_symbols,
        documented_symbols,
        documented_symbol_details,
        undocumented_symbols,
    }
}

fn format_doc_node_kind(def: &DocNodeDef) -> String {
    match def {
        DocNodeDef::Namespace { .. } => "namespace",
        DocNodeDef::Class { .. } => "class",
        DocNodeDef::Function { .. } => "function",
        DocNodeDef::Variable { .. } => "variable",
        DocNodeDef::Interface { .. } => "interface",
        DocNodeDef::TypeAlias { .. } => "type-alias",
        DocNodeDef::Enum { .. } => "enum",
        DocNodeDef::ModuleDoc => "module-doc",
        DocNodeDef::Import { .. } => "import",
        DocNodeDef::Reference { .. } => "reference",
    }
    .to_string()
}

/// Build doc nodes for a package version using in-memory source files, mirroring
/// the server-side compilation pipeline.
#[cfg(not(target_arch = "wasm32"))]
pub fn generate_doc_nodes_from_files(
    scope: &str,
    package: &str,
    version: &str,
    exports: &IndexMap<String, String>,
    imports: &IndexMap<String, String>,
    files: &HashMap<String, Vec<u8>>,
) -> Result<DocNodesByUrl> {
    generate_doc_nodes_from_files_impl(scope, package, version, exports, imports, files)
}

/// Async version for WASM
#[cfg(target_arch = "wasm32")]
pub async fn generate_doc_nodes_from_files(
    scope: &str,
    package: &str,
    version: &str,
    exports: &IndexMap<String, String>,
    imports: &IndexMap<String, String>,
    files: &HashMap<String, Vec<u8>>,
) -> Result<DocNodesByUrl> {
    generate_doc_nodes_from_files_async(scope, package, version, exports, imports, files).await
}

#[cfg(not(target_arch = "wasm32"))]
fn generate_doc_nodes_from_files_impl(
    scope: &str,
    package: &str,
    version: &str,
    exports: &IndexMap<String, String>,
    imports: &IndexMap<String, String>,
    files: &HashMap<String, Vec<u8>>,
) -> Result<DocNodesByUrl> {
    TokioRuntimeBuilder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(generate_doc_nodes_core(scope, package, version, exports, imports, files))
}

#[cfg(target_arch = "wasm32")]
async fn generate_doc_nodes_from_files_async(
    scope: &str,
    package: &str,
    version: &str,
    exports: &IndexMap<String, String>,
    imports: &IndexMap<String, String>,
    files: &HashMap<String, Vec<u8>>,
) -> Result<DocNodesByUrl> {
    generate_doc_nodes_core(scope, package, version, exports, imports, files).await
}

/// Core async implementation shared by both WASM and non-WASM builds.
async fn generate_doc_nodes_core(
    scope: &str,
    package: &str,
    version: &str,
    exports: &IndexMap<String, String>,
    imports: &IndexMap<String, String>,
    files: &HashMap<String, Vec<u8>>,
) -> Result<DocNodesByUrl> {
    let base_url = Url::parse("memory://jsr/").expect("valid base url");
    let member_version =
        Version::parse_standard(version).with_context(|| format!("invalid version '{version}'"))?;

    let mut roots = Vec::new();
    for (_name, export_path) in exports.iter() {
        let normalized = normalize_export_target(export_path);
        let specifier = base_url
            .join(&normalized)
            .with_context(|| format!("invalid export path '{export_path}'"))?;
        roots.push(specifier);
    }

    if roots.is_empty() {
        return Ok(IndexMap::new());
    }

    let module_analyzer = ModuleAnalyzer::default();

    let mut graph = ModuleGraph::new(GraphKind::All);
    let workspace_member = WorkspaceMember {
        base: base_url.clone(),
        name: StackString::from_string(format!("@{scope}/{package}")),
        version: Some(member_version),
        exports: exports.clone(),
    };

    let loader = MemoryLoader { files };
    let resolver = JsrInPackageResolver {
        member: workspace_member,
        imports: imports.clone(),
    };

    let jsr_version_resolver = JsrVersionResolver::default();

    graph.build(
        roots.clone(),
        vec![],
        &loader,
        BuildOptions {
            is_dynamic: false,
            module_analyzer: &module_analyzer,
            file_system: &deno_graph::source::NullFileSystem,
            jsr_url_provider: &PassthroughJsrUrlProvider,
            jsr_version_resolver: Cow::Borrowed(&jsr_version_resolver),
            passthrough_jsr_specifiers: true,
            resolver: Some(&resolver),
            npm_resolver: None,
            reporter: None,
            executor: Default::default(),
            locker: None,
            skip_dynamic_deps: false,
            module_info_cacher: Default::default(),
            unstable_bytes_imports: false,
            unstable_text_imports: false,
            jsr_metadata_store: None,
        },
    ).await;

    graph.valid().with_context(|| "invalid module graph")?;

    let parser = deno_doc::DocParser::new(
        &graph,
        &module_analyzer.analyzer,
        &roots,
        deno_doc::DocParserOptions {
            diagnostics: false,
            private: false,
        },
    )?;

    let doc_nodes = parser.parse()?;
    Ok(doc_nodes)
}

/// Generate doc nodes from a local JSR package directory
#[cfg(not(target_arch = "wasm32"))]
pub fn generate_doc_nodes_from_local_path(local_path: &Path) -> Result<DocNodesByUrl> {
    use std::fs;

    info!("Loading package from local path: {}", local_path.display());

    // Read and parse deno.json
    let deno_json_path = local_path.join("deno.json");
    if !deno_json_path.exists() {
        bail!("deno.json not found at {}", deno_json_path.display());
    }

    debug!("Reading deno.json from {}", deno_json_path.display());
    let deno_json_content = fs::read_to_string(&deno_json_path)
        .with_context(|| format!("failed to read deno.json at {}", deno_json_path.display()))?;

    let deno_json: serde_json::Value = serde_json::from_str(&deno_json_content)
        .context("failed to parse deno.json")?;

    // Extract package info
    let name = deno_json["name"]
        .as_str()
        .ok_or_else(|| anyhow!("deno.json missing 'name' field"))?;

    let version = deno_json["version"]
        .as_str()
        .ok_or_else(|| anyhow!("deno.json missing 'version' field"))?;

    // Parse scope and package name from @scope/package format
    let (scope, package) = parse_package_name(name)?;

    debug!("Package: @{}/{} v{}", scope, package, version);

    // Extract exports
    let exports_obj = deno_json["exports"]
        .as_object()
        .ok_or_else(|| anyhow!("deno.json missing 'exports' field"))?;

    let mut exports = IndexMap::new();
    for (key, value) in exports_obj {
        let export_path = value
            .as_str()
            .ok_or_else(|| anyhow!("export value for '{}' is not a string", key))?;
        exports.insert(key.clone(), export_path.to_string());
    }

    debug!("Found {} export(s)", exports.len());

    // Extract imports (import map) if present
    let mut imports = IndexMap::new();
    if let Some(imports_obj) = deno_json["imports"].as_object() {
        for (key, value) in imports_obj {
            if let Some(import_path) = value.as_str() {
                imports.insert(key.clone(), import_path.to_string());
            }
        }
        debug!("Found {} import map entries", imports.len());
    }

    // Collect all TypeScript/JavaScript files
    let mut files = HashMap::new();
    collect_source_files(local_path, local_path, &mut files)?;

    debug!("Collected {} file(s)", files.len());

    // Generate doc nodes
    generate_doc_nodes_from_files(&scope, &package, version, &exports, &imports, &files)
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_package_name(name: &str) -> Result<(String, String)> {
    let trimmed = name.trim().strip_prefix('@').unwrap_or(name);
    let (scope, package) = trimmed
        .split_once('/')
        .ok_or_else(|| anyhow!("package name must be in the form @scope/package"))?;

    if scope.is_empty() || package.is_empty() {
        bail!("invalid package name: {}", name);
    }

    Ok((scope.to_string(), package.to_string()))
}

#[cfg(not(target_arch = "wasm32"))]
fn collect_source_files(
    base_path: &Path,
    current_path: &Path,
    files: &mut HashMap<String, Vec<u8>>,
) -> Result<()> {
    use std::fs;

    if !current_path.exists() {
        return Ok(());
    }

    if current_path.is_file() {
        let extension = current_path.extension().and_then(|e| e.to_str());
        if matches!(extension, Some("ts") | Some("tsx") | Some("js") | Some("jsx") | Some("mts") | Some("cts")) {
            let relative_path = current_path.strip_prefix(base_path)
                .with_context(|| format!("failed to compute relative path for {}", current_path.display()))?;

            let key = format!("/{}", relative_path.to_string_lossy().replace('\\', "/"));

            debug!("Reading file: {}", key);
            let content = fs::read(current_path)
                .with_context(|| format!("failed to read file {}", current_path.display()))?;

            files.insert(key, content);
        }
        return Ok(());
    }

    if current_path.is_dir() {
        // Skip common directories that shouldn't be analyzed
        let dir_name = current_path.file_name().and_then(|n| n.to_str());
        if matches!(dir_name, Some("node_modules") | Some("target") | Some(".git") | Some("dist") | Some("docs")) {
            debug!("Skipping directory: {}", current_path.display());
            return Ok(());
        }

        for entry in fs::read_dir(current_path)
            .with_context(|| format!("failed to read directory {}", current_path.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            collect_source_files(base_path, &path, files)?;
        }
    }

    Ok(())
}

fn normalize_export_target(path: &str) -> String {
    let path = path.trim();
    let path = path.strip_prefix("./").unwrap_or(path);
    let path = path.strip_prefix('/').unwrap_or(path);
    path.to_string()
}

struct ModuleParser(DefaultEsParser);

impl Default for ModuleParser {
    fn default() -> Self {
        Self(DefaultEsParser)
    }
}

impl deno_graph::ast::EsParser for ModuleParser {
    fn parse_program(
        &self,
        options: ParseOptions,
    ) -> Result<ParsedSource, deno_ast::ParseDiagnostic> {
        let source = self.0.parse_program(options)?;
        if let Some(err) = source.diagnostics().first() {
            return Err(err.clone());
        }
        Ok(source)
    }
}

struct ModuleAnalyzer {
    analyzer: CapturingModuleAnalyzer,
    module_info: RefCell<HashMap<Url, ModuleInfo>>,
}

impl Default for ModuleAnalyzer {
    fn default() -> Self {
        Self {
            analyzer: CapturingModuleAnalyzer::new(Some(Box::new(ModuleParser::default())), None),
            module_info: Default::default(),
        }
    }
}

#[async_trait(?Send)]
impl deno_graph::analysis::ModuleAnalyzer for ModuleAnalyzer {
    async fn analyze(
        &self,
        specifier: &ModuleSpecifier,
        source: Arc<str>,
        media_type: MediaType,
    ) -> Result<ModuleInfo, JsErrorBox> {
        let module_info = self.analyzer.analyze(specifier, source, media_type).await?;
        self.module_info
            .borrow_mut()
            .insert(specifier.clone(), module_info.clone());
        Ok(module_info)
    }
}

struct MemoryLoader<'a> {
    files: &'a HashMap<String, Vec<u8>>,
}

impl MemoryLoader<'_> {
    fn load_sync(&self, specifier: &ModuleSpecifier) -> LoadResult {
        match specifier.scheme() {
            "memory" => {
                let path = specifier.path();
                let Some(bytes) = self.files.get(path).cloned() else {
                    return Ok(None);
                };
                Ok(Some(LoadResponse::Module {
                    content: bytes.into(),
                    mtime: None,
                    specifier: specifier.clone(),
                    maybe_headers: None,
                }))
            }
            "data" => load_data_url(specifier)
                .map_err(|err| LoadError::Other(Arc::new(JsErrorBox::from_err(err)))),
            "http" | "https" | "jsr" | "npm" | "node" | "bun" | "virtual" | "cloudflare" => {
                Ok(Some(LoadResponse::External {
                    specifier: specifier.clone(),
                }))
            }
            _ => Ok(None),
        }
    }
}

impl Loader for MemoryLoader<'_> {
    fn load(&self, specifier: &ModuleSpecifier, _options: LoadOptions) -> LoadFuture {
        let result = self.load_sync(specifier);
        async move { result }.boxed()
    }
}

struct PassthroughJsrUrlProvider;

impl JsrUrlProvider for PassthroughJsrUrlProvider {
    fn url(&self) -> &Url {
        unreachable!("passthrough mode should prevent JSR URL resolution")
    }

    fn package_url(&self, _nv: &deno_semver::package::PackageNv) -> Url {
        unreachable!("passthrough mode should prevent JSR URL resolution")
    }

    fn package_url_to_nv(&self, _url: &Url) -> Option<deno_semver::package::PackageNv> {
        None
    }
}

#[derive(Debug)]
struct JsrInPackageResolver {
    member: WorkspaceMember,
    imports: IndexMap<String, String>,
}

impl Resolver for JsrInPackageResolver {
    fn resolve(
        &self,
        specifier_text: &str,
        referrer_range: &deno_graph::Range,
        _kind: deno_graph::source::ResolutionKind,
    ) -> Result<ModuleSpecifier, ResolveError> {
        if let Ok(package_ref) = JsrPackageReqReference::from_str(specifier_text)
            && self.member.name == package_ref.req().name
            && self
                .member
                .version
                .as_ref()
                .map(|v| package_ref.req().version_req.matches(v))
                .unwrap_or(true)
        {
            let export_name = package_ref.sub_path().unwrap_or(".");
            let Some(export) = self.member.exports.get(export_name) else {
                return Err(ResolveError::Other(JsErrorBox::generic(format!(
                    "export '{}' not found in jsr:{}",
                    export_name, self.member.name
                ))));
            };
            return self
                .member
                .base
                .join(export)
                .map_err(|err| ResolveError::Other(JsErrorBox::generic(err.to_string())));
        }

        // Check import map for bare specifiers
        if !specifier_text.starts_with("./")
            && !specifier_text.starts_with("../")
            && !specifier_text.starts_with("/")
            && !specifier_text.contains("://")
        {
            // Try to match the import map
            for (key, value) in &self.imports {
                if specifier_text == key || specifier_text.starts_with(&format!("{}/", key)) {
                    // Replace the matched prefix with the mapped value
                    let mapped = if specifier_text == key {
                        value.clone()
                    } else {
                        specifier_text.replacen(key, value, 1)
                    };

                    // For npm: specifiers, we'll allow them through (deno_graph will handle them)
                    if mapped.starts_with("npm:") || mapped.starts_with("jsr:") {
                        return ModuleSpecifier::parse(&mapped)
                            .map_err(|err| ResolveError::Other(JsErrorBox::generic(err.to_string())));
                    }
                }
            }
        }

        resolve_import(specifier_text, &referrer_range.specifier)
            .map_err(|err| ResolveError::Other(JsErrorBox::generic(err.to_string())))
    }
}
