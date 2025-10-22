use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use deno_ast::{MediaType, ModuleSpecifier, ParsedSource};
use deno_doc::node::DeclarationKind;
use deno_doc::{DocNode, DocNodeDef};
use deno_error::JsErrorBox;
use deno_graph::analysis::ModuleInfo;
use deno_graph::ast::{CapturingModuleAnalyzer, DefaultEsParser, ParseOptions};
use deno_graph::source::{
    JsrUrlProvider, LoadError, LoadFuture, LoadOptions, LoadResponse, LoadResult, Loader,
    ResolveError, Resolver, load_data_url,
};
use deno_graph::{BuildOptions, GraphKind, ModuleGraph, WorkspaceMember, resolve_import};
use deno_semver::{StackString, Version, jsr::JsrPackageReqReference};
use futures::FutureExt;
use indexmap::IndexMap;
use tokio::runtime::Builder as TokioRuntimeBuilder;
use url::Url;

/// Mapping of module specifiers to the DocNodes extracted from that module.
pub type DocNodesByUrl = IndexMap<ModuleSpecifier, Vec<DocNode>>;

/// Summary of documentation coverage for a package.
#[derive(Debug, Clone, PartialEq)]
pub struct DocumentationCoverage {
    pub total_symbols: usize,
    pub documented_symbols: usize,
    pub documented_symbol_details: Vec<DocumentedSymbol>,
    pub undocumented_symbols: Vec<UndocumentedSymbol>,
}

/// Representation of an undocumented exported symbol for reporting purposes.
#[derive(Debug, Clone, PartialEq)]
pub struct UndocumentedSymbol {
    pub specifier: ModuleSpecifier,
    pub name: String,
    pub kind: String,
    pub declaration_kind: Option<String>,
    pub location: Option<SymbolLocation>,
}

/// Representation of a documented exported symbol for reporting purposes.
#[derive(Debug, Clone, PartialEq)]
pub struct DocumentedSymbol {
    pub specifier: ModuleSpecifier,
    pub name: String,
    pub kind: String,
    pub declaration_kind: Option<String>,
    pub location: Option<SymbolLocation>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SymbolLocation {
    pub filename: String,
    pub line: u32,
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

    for (specifier, nodes) in doc_nodes.iter() {
        for node in nodes {
            if matches!(node.def, DocNodeDef::ModuleDoc | DocNodeDef::Import { .. }) {
                continue;
            }

            if node.declaration_kind == DeclarationKind::Private {
                continue;
            }

            total_symbols += 1;

            if node.js_doc.is_empty() {
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
            } else {
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
            }
        }
    }

    // If there are no symbols, consider the package fully documented, matching
    // the behavior in the JSR backend.
    if total_symbols == 0 {
        documented_symbols = 0;
    }

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
pub fn generate_doc_nodes_from_files(
    scope: &str,
    package: &str,
    version: &str,
    exports: &IndexMap<String, String>,
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
    };

    TokioRuntimeBuilder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(graph.build(
            roots.clone(),
            vec![],
            &loader,
            BuildOptions {
                is_dynamic: false,
                module_analyzer: &module_analyzer,
                file_system: &deno_graph::source::NullFileSystem,
                jsr_url_provider: &PassthroughJsrUrlProvider,
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
        ));

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

        resolve_import(specifier_text, &referrer_range.specifier)
            .map_err(|err| ResolveError::Other(JsErrorBox::generic(err.to_string())))
    }
}
