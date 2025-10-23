//! Shared types used across CLI and WASM modules.

use anyhow::{anyhow, bail, Result};

/// Parsed package specification in the form `@scope/name[@version]`.
#[derive(Debug, Clone)]
pub struct PackageSpec {
    pub scope: String,
    pub package: String,
    pub version: Option<String>,
}

impl PackageSpec {
    /// Parse a package specifier string into structured components.
    ///
    /// Accepts formats:
    /// - `@scope/name`
    /// - `@scope/name@version`
    /// - `scope/name` (@ prefix is optional)
    pub fn parse(input: &str) -> Result<Self> {
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

/// Format a URL specifier to a displayable path string.
///
/// Strips the leading `/` if present, or returns the full URL if path is empty.
pub fn format_specifier(specifier: &url::Url) -> String {
    let path = specifier.path().trim_start_matches('/');
    if path.is_empty() {
        specifier.to_string()
    } else {
        path.to_string()
    }
}
