use super::{dedup, invalid};
use depscan_core::{Ecosystem, Package, ParseError, normalize_name};
use pep440_rs::{Version as Pep440Version, VersionSpecifiers};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

mod syntax;

use syntax::{ConstraintSpec, GlobalOption, IncludeKind, ParsedLine};

const MAX_INCLUDE_DEPTH: usize = 32;
const MAX_REQUIREMENTS_FILES: usize = 256;
const MAX_REQUIREMENTS_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Copy)]
struct RequirementsLimits {
    include_depth: usize,
    files: usize,
    bytes: u64,
}

impl Default for RequirementsLimits {
    fn default() -> Self {
        Self {
            include_depth: MAX_INCLUDE_DEPTH,
            files: MAX_REQUIREMENTS_FILES,
            bytes: MAX_REQUIREMENTS_BYTES,
        }
    }
}

pub(crate) fn parse(path: &Path) -> Result<Vec<Package>, ParseError> {
    parse_with_limits(path, RequirementsLimits::default())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileRole {
    Requirement,
    Constraint,
}

fn parse_with_limits(path: &Path, limits: RequirementsLimits) -> Result<Vec<Package>, ParseError> {
    let requested_root = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let root = fs::canonicalize(requested_root).map_err(|error| {
        invalid(
            requested_root,
            format!("cannot canonicalize requirements scan root: {error}"),
        )
    })?;
    let metadata = fs::metadata(&root).map_err(|error| {
        invalid(
            requested_root,
            format!("cannot inspect requirements scan root: {error}"),
        )
    })?;
    if !metadata.is_dir() {
        return Err(invalid(
            requested_root,
            "requirements scan root is not a directory",
        ));
    }

    let mut parser = RequirementsParser {
        root,
        limits,
        active: Vec::new(),
        files_read: 0,
        bytes_read: 0,
        registry_origin_ambiguous: false,
        range_resolution_ambiguous: false,
        constraints: BTreeMap::new(),
    };
    let mut packages = parser.parse_file(path, FileRole::Requirement)?;
    apply_constraints(path, &mut packages, &parser.constraints)?;
    if parser.registry_origin_ambiguous {
        for package in &mut packages {
            package.enrichable = false;
        }
    } else if parser.range_resolution_ambiguous {
        for package in &mut packages {
            if package.resolved_from_range {
                package.enrichable = false;
            }
        }
    }
    Ok(dedup(packages))
}

struct RequirementsParser {
    root: PathBuf,
    limits: RequirementsLimits,
    active: Vec<PathBuf>,
    files_read: usize,
    bytes_read: u64,
    registry_origin_ambiguous: bool,
    range_resolution_ambiguous: bool,
    constraints: BTreeMap<String, Vec<ConstraintSpec>>,
}

fn apply_constraints(
    root: &Path,
    packages: &mut [Package],
    constraints: &BTreeMap<String, Vec<ConstraintSpec>>,
) -> Result<(), ParseError> {
    for package in packages {
        let Some(additional) = constraints.get(&package.name) else {
            continue;
        };
        if let Some(declared) = package.manifest_constraint.take() {
            let raw = std::iter::once(declared.raw())
                .chain(additional.iter().map(|constraint| constraint.raw.as_str()))
                .filter(|constraint| *constraint != "*")
                .collect::<Vec<_>>()
                .join(", ");
            let normalized = std::iter::once(declared.normalized())
                .chain(
                    additional
                        .iter()
                        .map(|constraint| constraint.normalized.as_str()),
                )
                .collect::<Vec<_>>()
                .join(",");
            let normalized = normalized
                .parse::<VersionSpecifiers>()
                .map_err(|error| {
                    invalid(
                        root,
                        format!(
                            "combined constraint for {:?} is invalid: {error}",
                            package.display_name
                        ),
                    )
                })?
                .to_string();
            package.set_normalized_manifest_constraint(
                if raw.is_empty() { "*" } else { &raw },
                normalized,
            );
        } else if !package.resolved_from_range {
            let normalized = additional
                .iter()
                .map(|constraint| constraint.normalized.as_str())
                .collect::<Vec<_>>()
                .join(",");
            let specifiers = normalized.parse::<VersionSpecifiers>().map_err(|error| {
                invalid(
                    root,
                    format!(
                        "constraint for {:?} is invalid: {error}",
                        package.display_name
                    ),
                )
            })?;
            let version = package.version.parse::<Pep440Version>().map_err(|error| {
                invalid(
                    root,
                    format!(
                        "pinned version for {:?} is invalid: {error}",
                        package.display_name
                    ),
                )
            })?;
            if !specifiers.contains(&version) {
                return Err(invalid(
                    root,
                    format!(
                        "pinned requirement {:?}=={} conflicts with its constraints",
                        package.display_name, package.version
                    ),
                ));
            }
        }
    }
    Ok(())
}

impl RequirementsParser {
    fn parse_file(&mut self, requested: &Path, role: FileRole) -> Result<Vec<Package>, ParseError> {
        let depth = self.active.len();
        if depth > self.limits.include_depth {
            return Err(self.rejected(
                requested,
                format!(
                    "requirements include depth {depth} exceeds the maximum of {}",
                    self.limits.include_depth
                ),
            ));
        }
        if self.files_read >= self.limits.files {
            return Err(self.rejected(
                requested,
                format!(
                    "requirements file count exceeds the maximum of {}",
                    self.limits.files
                ),
            ));
        }

        let requested_metadata = fs::symlink_metadata(requested).map_err(|error| {
            self.rejected(
                requested,
                format!("cannot inspect requirements file: {error}"),
            )
        })?;
        if requested_metadata.file_type().is_symlink() {
            return Err(self.rejected(
                requested,
                "requirements file is a symbolic link; symbolic includes are not allowed",
            ));
        }
        if !requested_metadata.is_file() {
            return Err(self.rejected(requested, "requirements include is not a regular file"));
        }

        let canonical = fs::canonicalize(requested).map_err(|error| {
            self.rejected(
                requested,
                format!("cannot canonicalize requirements file: {error}"),
            )
        })?;
        if !canonical.starts_with(&self.root) {
            return Err(self.rejected(
                requested,
                format!(
                    "requirements include resolves outside scan root {}",
                    self.root.display()
                ),
            ));
        }
        if self.active.contains(&canonical) {
            return Err(self.rejected(&canonical, "requirements include cycle detected"));
        }

        self.active.push(canonical.clone());
        let result = self.read_and_parse(&canonical, role);
        self.active.pop();
        result
    }

    fn read_and_parse(
        &mut self,
        canonical: &Path,
        role: FileRole,
    ) -> Result<Vec<Package>, ParseError> {
        let file = File::open(canonical).map_err(|error| {
            self.current_error(canonical, format!("cannot open requirements file: {error}"))
        })?;
        let metadata = file.metadata().map_err(|error| {
            self.current_error(
                canonical,
                format!("cannot inspect open requirements file: {error}"),
            )
        })?;
        if !metadata.is_file() {
            return Err(self.current_error(canonical, "requirements include is not a regular file"));
        }

        let remaining = self.limits.bytes.saturating_sub(self.bytes_read);
        if metadata.len() > remaining {
            return Err(self.current_error(
                canonical,
                format!(
                    "requirements input exceeds the maximum total of {} bytes",
                    self.limits.bytes
                ),
            ));
        }

        let mut bytes = Vec::new();
        file.take(remaining.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| {
                self.current_error(canonical, format!("cannot read requirements file: {error}"))
            })?;
        let byte_count = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if byte_count > remaining {
            return Err(self.current_error(
                canonical,
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
                canonical,
                format!("requirements file is not valid UTF-8: {error}"),
            )
        })?;
        self.parse_text(canonical, &text, role)
    }

    fn parse_text(
        &mut self,
        canonical: &Path,
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
        let base = canonical.parent().unwrap_or(&self.root).to_path_buf();
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
                    let requested = if include_path.is_absolute() {
                        include_path.to_path_buf()
                    } else {
                        base.join(include_path)
                    };
                    let include_role = match kind {
                        IncludeKind::Requirement => role,
                        IncludeKind::Constraint => FileRole::Constraint,
                    };
                    packages.extend(self.parse_file(&requested, include_role)?);
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

    fn rejected(&self, requested: &Path, message: impl AsRef<str>) -> ParseError {
        invalid(
            requested,
            format!(
                "{}; requirements include chain: {}",
                message.as_ref(),
                self.include_chain(Some(requested))
            ),
        )
    }

    fn current_error(&self, path: &Path, message: impl AsRef<str>) -> ParseError {
        invalid(
            path,
            format!(
                "{}; requirements include chain: {}",
                message.as_ref(),
                self.include_chain(None)
            ),
        )
    }

    fn include_chain(&self, next: Option<&Path>) -> String {
        self.active
            .iter()
            .map(|path| path.display().to_string())
            .chain(next.into_iter().map(|path| path.display().to_string()))
            .collect::<Vec<_>>()
            .join(" -> ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::symlink as symlink_file;
    #[cfg(windows)]
    use std::os::windows::fs::symlink_file;

    fn write(path: &Path, text: impl AsRef<[u8]>) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, text).unwrap();
    }

    fn names(packages: &[Package]) -> Vec<&str> {
        packages
            .iter()
            .map(|package| package.name.as_str())
            .collect()
    }

    #[test]
    fn parses_nested_relative_and_long_form_includes() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("requirements.txt");
        write(
            &root,
            "root-package==1.0\n-r nested/base.txt\n--requirement nested/more.txt\n",
        );
        write(
            &directory.path().join("nested/base.txt"),
            "base-package==2.0\n-r ../shared.txt\n",
        );
        write(
            &directory.path().join("nested/more.txt"),
            "more-package==3.0\n",
        );
        write(
            &directory.path().join("shared.txt"),
            "shared-package==4.0\n",
        );

        let packages = parse(&root).unwrap();

        assert_eq!(
            names(&packages),
            vec![
                "base-package",
                "more-package",
                "root-package",
                "shared-package"
            ]
        );
    }

    #[test]
    fn preserves_pep440_constraint_without_extras_or_environment_marker() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("requirements.txt");
        write(
            &root,
            "range-package[security]>=1.0,<2.0,!=1.5; python_version >= '3.11'\n",
        );

        let packages = parse(&root).unwrap();

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "range-package");
        assert_eq!(packages[0].version, ">=1.0,<2.0,!=1.5");
        let constraint = packages[0].manifest_constraint.as_ref().unwrap();
        assert_eq!(constraint.raw(), ">=1.0,<2.0,!=1.5");
        assert_eq!(constraint.normalized(), ">=1.0, !=1.5, <2.0");
    }

    #[test]
    fn rejects_parent_escape_without_exposing_outside_contents() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        let root = project.join("requirements.txt");
        let outside = directory.path().join("outside.txt");
        let secret = "outside-secret-must-not-appear==9.9.9";
        write(&root, "-r ../outside.txt\n");
        write(&outside, secret);

        let error = parse(&root).unwrap_err().to_string();

        assert!(error.contains("outside scan root"));
        assert!(error.contains("requirements include chain"));
        assert!(error.contains("outside.txt"));
        assert!(!error.contains(secret));
    }

    #[test]
    fn rejects_absolute_external_include() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        let root = project.join("requirements.txt");
        let outside = directory.path().join("absolute-outside.txt");
        write(&outside, "outside==1\n");
        write(&root, format!("-r {}\n", outside.display()));

        let error = parse(&root).unwrap_err().to_string();

        assert!(error.contains("outside scan root"));
        assert!(error.contains(&outside.to_string_lossy().into_owned()));
    }

    #[test]
    fn accepts_native_absolute_include_that_remains_inside_root() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("requirements.txt");
        let included = directory.path().join("absolute-inside.txt");
        write(&included, "inside==1\n");
        write(&root, format!("--requirement {}\n", included.display()));

        let packages = parse(&root).unwrap();

        assert_eq!(names(&packages), vec!["inside"]);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn rejects_symbolic_include_before_reading_its_target() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        let root = project.join("requirements.txt");
        let outside = directory.path().join("outside.txt");
        let linked = project.join("linked.txt");
        write(&root, "-r linked.txt\n");
        write(&outside, "symlink-secret==1\n");
        if let Err(error) = symlink_file(&outside, &linked) {
            #[cfg(windows)]
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                return;
            }
            panic!("create requirements symlink: {error}");
        }

        let error = parse(&root).unwrap_err().to_string();

        assert!(error.contains("symbolic link"));
        assert!(error.contains("linked.txt"));
        assert!(!error.contains("symlink-secret"));
    }

    #[test]
    fn detects_canonical_alias_cycle_with_full_chain() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("requirements.txt");
        let nested = directory.path().join("nested/requirements.txt");
        write(&root, "-r nested/requirements.txt\n");
        write(&nested, "-r .././requirements.txt\n");

        let error = parse(&root).unwrap_err().to_string();

        assert!(error.contains("include cycle detected"));
        assert!(error.contains("requirements include chain"));
        assert_eq!(error.matches("requirements.txt").count(), 4);
    }

    #[test]
    fn allows_repeated_include_when_it_is_not_active() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("requirements.txt");
        write(&root, "-r shared.txt\n-r shared.txt\n");
        write(&directory.path().join("shared.txt"), "shared==1\n");

        let packages = parse(&root).unwrap();

        assert_eq!(names(&packages), vec!["shared"]);
    }

    #[test]
    fn rejects_missing_and_non_file_includes_with_chain() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("requirements.txt");
        write(&root, "-r missing.txt\n");

        let missing = parse(&root).unwrap_err().to_string();
        assert!(missing.contains("cannot inspect requirements file"));
        assert!(missing.contains("missing.txt"));
        assert!(missing.contains("requirements include chain"));

        fs::create_dir(directory.path().join("included-directory")).unwrap();
        write(&root, "-r included-directory\n");
        let directory_error = parse(&root).unwrap_err().to_string();
        assert!(directory_error.contains("not a regular file"));
        assert!(directory_error.contains("included-directory"));
    }

    #[test]
    fn enforces_include_depth_limit() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("requirements.txt");
        write(&root, "-r one.txt\n");
        write(&directory.path().join("one.txt"), "-r two.txt\n");
        write(&directory.path().join("two.txt"), "-r three.txt\n");
        write(&directory.path().join("three.txt"), "leaf==1\n");

        let error = parse_with_limits(
            &root,
            RequirementsLimits {
                include_depth: 2,
                ..RequirementsLimits::default()
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("include depth 3 exceeds the maximum of 2"));
        assert!(error.contains("three.txt"));
    }

    #[test]
    fn enforces_file_count_limit_across_repeated_includes() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("requirements.txt");
        write(&root, "-r shared.txt\n-r shared.txt\n");
        write(&directory.path().join("shared.txt"), "shared==1\n");

        let error = parse_with_limits(
            &root,
            RequirementsLimits {
                files: 2,
                ..RequirementsLimits::default()
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("file count exceeds the maximum of 2"));
        assert!(error.contains("shared.txt"));
    }

    #[test]
    fn enforces_total_byte_limit_before_reading_included_file() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("requirements.txt");
        let root_text = "-r included.txt\n";
        write(&root, root_text);
        write(&directory.path().join("included.txt"), "included==1\n");

        let error = parse_with_limits(
            &root,
            RequirementsLimits {
                bytes: u64::try_from(root_text.len()).unwrap(),
                ..RequirementsLimits::default()
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("maximum total"));
        assert!(error.contains("included.txt"));
    }
}
