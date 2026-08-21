//! Stable report renderers for human terminals and CI integrations.

mod formatting;
mod markdown;
mod sarif;
mod summary;
mod table;
mod totals;

pub use markdown::render_markdown;
pub use sarif::render_sarif;
pub use summary::render_summary;
pub use table::render_table;
pub use totals::Totals;

use depscan_core::ScanDocument;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutputFormat {
    Table,
    Markdown,
    Json,
    Sarif,
    Summary,
}

impl OutputFormat {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "table" => Some(Self::Table),
            "markdown" => Some(Self::Markdown),
            "json" => Some(Self::Json),
            "sarif" => Some(Self::Sarif),
            "summary" => Some(Self::Summary),
            _ => None,
        }
    }

    pub fn infer(path: &Path) -> Option<Self> {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("md" | "markdown") => Some(Self::Markdown),
            Some("json") => Some(Self::Json),
            Some("sarif") => Some(Self::Sarif),
            Some("txt" | "log") => Some(Self::Summary),
            _ => None,
        }
    }
}

pub fn render(
    document: &ScanDocument,
    format: OutputFormat,
    color: bool,
) -> Result<String, serde_json::Error> {
    match format {
        OutputFormat::Table => Ok(render_table(document, color)),
        OutputFormat::Markdown => Ok(render_markdown(document)),
        OutputFormat::Json => serde_json::to_string_pretty(document),
        OutputFormat::Sarif => serde_json::to_string_pretty(&render_sarif(document)),
        OutputFormat::Summary => Ok(render_summary(document)),
    }
}

#[cfg(test)]
mod tests;
