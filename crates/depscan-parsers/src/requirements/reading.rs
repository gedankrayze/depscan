use super::*;

impl RequirementsParser<'_> {
    pub(super) fn read_and_parse(
        &mut self,
        opened: &mut OpenRequirementsFile,
        role: FileRole,
    ) -> Result<Vec<Package>, ParseError> {
        let metadata = opened.file.metadata().map_err(|error| {
            self.current_error(
                &opened.display,
                format!("cannot inspect open requirements file: {error}"),
            )
        })?;
        let remaining = self.limits.bytes.saturating_sub(self.bytes_read);
        if metadata.len() > remaining {
            return Err(self.current_error(
                &opened.display,
                format!(
                    "requirements input exceeds the maximum total of {} bytes",
                    self.limits.bytes
                ),
            ));
        }

        (self.hook)(ReadBoundary::BeforeRead, &opened.relative, &opened.display)?;
        let mut bytes = Vec::new();
        (&mut opened.file)
            .take(remaining.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| {
                self.current_error(
                    &opened.display,
                    format!("cannot read requirements file: {error}"),
                )
            })?;
        (self.hook)(ReadBoundary::AfterRead, &opened.relative, &opened.display)?;
        self.revalidate_file(opened)?;

        let byte_count = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if byte_count > remaining {
            return Err(self.current_error(
                &opened.display,
                format!(
                    "requirements input exceeds the maximum total of {} bytes",
                    self.limits.bytes
                ),
            ));
        }
        self.files_read += 1;
        self.bytes_read += byte_count;

        let text = String::from_utf8(bytes).map_err(|error| {
            self.current_error(
                &opened.display,
                format!("requirements file is not valid UTF-8: {error}"),
            )
        })?;
        self.parse_text(
            &opened.display,
            &opened.relative,
            &opened.parent,
            &text,
            role,
        )
    }

    pub(super) fn parse_text(
        &mut self,
        canonical: &Path,
        relative: &Path,
        parent: &Arc<DirectoryCapability>,
        text: &str,
        role: FileRole,
    ) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();
        let logical_lines = syntax::logical_lines(text).map_err(|error| {
            self.current_error(
                canonical,
                format!("invalid requirements syntax: {}", error.message()),
            )
        })?;
        let base = canonical
            .parent()
            .unwrap_or(&self.root.canonical)
            .to_path_buf();
        for logical in logical_lines {
            let parsed = syntax::parse_line(&logical.text, &base).map_err(|error| {
                self.current_error(
                    canonical,
                    format!(
                        "invalid requirements syntax at line {}: {}",
                        logical.number,
                        error.message()
                    ),
                )
            })?;
            match parsed {
                ParsedLine::Empty | ParsedLine::Global(GlobalOption::Ignored) => {}
                ParsedLine::Global(GlobalOption::AmbiguousRegistry) => {
                    self.registry_origin_ambiguous = true;
                }
                ParsedLine::Global(GlobalOption::AmbiguousRangeResolution) => {
                    self.range_resolution_ambiguous = true;
                    tracing::warn!(
                        source_file = %canonical.display(),
                        line = logical.number,
                        "requirements option changes release selection; range freshness is disabled"
                    );
                }
                ParsedLine::Include { kind, target } => {
                    if target.contains("://") {
                        return Err(self.current_error(
                            canonical,
                            format!(
                                "remote requirements include at line {} is not supported; includes must remain inside the scan root",
                                logical.number
                            ),
                        ));
                    }
                    let include_path = Path::new(&target);
                    let requested_display = if include_path.is_absolute() {
                        include_path.to_path_buf()
                    } else {
                        base.join(include_path)
                    };
                    let requested =
                        self.include_relative(relative, include_path)
                            .ok_or_else(|| {
                                self.rejected(
                                    &requested_display,
                                    format!(
                                        "requirements include resolves outside scan root {}",
                                        self.root.canonical.display()
                                    ),
                                )
                            })?;
                    let include_role = match kind {
                        IncludeKind::Requirement => role,
                        IncludeKind::Constraint => FileRole::Constraint,
                    };
                    packages.extend(self.parse_file(&requested, include_role, parent)?);
                }
                ParsedLine::Package(spec) => {
                    if spec.has_marker {
                        tracing::warn!(
                            source_file = %canonical.display(),
                            line = logical.number,
                            "requirements environment marker is assumed true"
                        );
                    }
                    if role == FileRole::Constraint {
                        if !spec.constraint_compatible {
                            return Err(self.current_error(
                                canonical,
                                format!(
                                    "invalid constraint at line {}: constraints must be named, non-editable requirements without extras or direct URLs",
                                    logical.number
                                ),
                            ));
                        }
                        let constraint = spec.registry_constraint.ok_or_else(|| {
                            self.current_error(
                                canonical,
                                format!(
                                    "invalid constraint at line {}: constraint has no registry version expression",
                                    logical.number
                                ),
                            )
                        })?;
                        self.constraints
                            .entry(normalize_name(Ecosystem::PyPI, &spec.display_name))
                            .or_default()
                            .push(constraint);
                        continue;
                    }
                    let mut package = Package::new(
                        Ecosystem::PyPI,
                        spec.display_name,
                        spec.version,
                        canonical.to_path_buf(),
                    );
                    package.direct = true;
                    package.dev_known = false;
                    package.enrichable = spec.enrichable;
                    package.resolved_from_range = spec.resolved_from_range;
                    if spec.resolved_from_range
                        && let Some(constraint) = spec.registry_constraint
                    {
                        package.set_normalized_manifest_constraint(
                            constraint.raw,
                            constraint.normalized,
                        );
                    }
                    packages.push(package);
                }
            }
        }
        Ok(packages)
    }
}
