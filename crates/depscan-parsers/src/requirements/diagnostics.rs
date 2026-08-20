use super::*;

impl RequirementsParser<'_> {
    pub(super) fn include_relative(&self, including: &Path, requested: &Path) -> Option<PathBuf> {
        if requested.is_absolute() {
            let requested = normalize_lexical(requested)?;
            return strip_root_prefix(&requested, &self.root.canonical)
                .or_else(|| strip_root_prefix(&requested, &self.root.requested_absolute))
                .and_then(|relative| normalize_relative(&relative));
        }
        let base = including.parent().unwrap_or_else(|| Path::new(""));
        normalize_relative(&base.join(requested))
    }

    pub(super) fn rejected(&self, requested: &Path, message: impl AsRef<str>) -> ParseError {
        invalid(
            requested,
            format!(
                "{}; requirements include chain: {}",
                message.as_ref(),
                self.include_chain(Some(requested))
            ),
        )
    }

    pub(super) fn current_error(&self, path: &Path, message: impl AsRef<str>) -> ParseError {
        invalid(
            path,
            format!(
                "{}; requirements include chain: {}",
                message.as_ref(),
                self.include_chain(None)
            ),
        )
    }

    pub(super) fn include_chain(&self, next: Option<&Path>) -> String {
        self.active
            .iter()
            .map(|active| active.display.display().to_string())
            .chain(next.into_iter().map(|path| path.display().to_string()))
            .collect::<Vec<_>>()
            .join(" -> ")
    }
}
