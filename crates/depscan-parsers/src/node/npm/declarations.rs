use super::*;

#[derive(Default)]
pub(crate) struct NpmDependencyDeclaration {
    pub(crate) nonregistry: bool,
    pub(crate) nonregistry_specification: Option<String>,
    pub(crate) registry_identity: Option<String>,
    pub(crate) registry_constraint: Option<String>,
}

#[derive(Default)]
pub(crate) struct NpmDependencyDeclarations {
    pub(crate) nonregistry: bool,
    pub(crate) nonregistry_specifications: BTreeMap<String, String>,
    pub(crate) registry_identities: BTreeMap<String, String>,
    pub(crate) registry_constraints: BTreeMap<String, String>,
}

impl NpmDependencyDeclarations {
    pub(crate) fn has_registry_declaration(&self) -> bool {
        !self.registry_identities.is_empty()
    }

    pub(crate) fn registry_identity_matches(&self, package_name: &str) -> bool {
        self.registry_identities
            .values()
            .all(|identity| identity == package_name)
    }

    pub(crate) fn non_root_registry_identity_matches(&self, package_name: &str) -> bool {
        self.registry_identities
            .iter()
            .filter(|(descriptor, _)| !descriptor.is_empty())
            .all(|(_, identity)| identity == package_name)
    }

    pub(crate) fn validate_non_root_registry_constraints(
        &self,
        version: &str,
    ) -> Result<(), String> {
        for (descriptor, constraint) in self
            .registry_constraints
            .iter()
            .filter(|(descriptor, _)| !descriptor.is_empty())
        {
            match latest_matching_version(Ecosystem::Npm, constraint, [version]) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return Err(format!(
                        "dependency constraint {constraint:?} from descriptor {descriptor:?} does not accept linked workspace version {version:?}"
                    ));
                }
                Err(error) => {
                    return Err(format!(
                        "dependency constraint {constraint:?} from descriptor {descriptor:?} cannot safely validate linked workspace version {version:?}: {error}"
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn has_non_root_registry_constraints(&self) -> bool {
        self.registry_constraints
            .keys()
            .any(|descriptor| !descriptor.is_empty())
    }

    pub(crate) fn validate_nonregistry_sources(
        &self,
        target: &str,
        proven_workspace_identity: bool,
    ) -> Result<(), String> {
        for (descriptor, specification) in &self.nonregistry_specifications {
            if descriptor.is_empty() && proven_workspace_identity {
                continue;
            }
            if specification
                .get(..10)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("workspace:"))
            {
                if proven_workspace_identity {
                    continue;
                }
                return Err(format!(
                    "workspace dependency source {specification:?} from descriptor {descriptor:?} cannot resolve to non-workspace link target {target:?}"
                ));
            }
            if npm_declared_local_target(descriptor, specification).as_deref() == Some(target) {
                continue;
            }
            return Err(format!(
                "non-registry dependency source {specification:?} from descriptor {descriptor:?} does not resolve to linked target {target:?}"
            ));
        }
        Ok(())
    }

    pub(crate) fn merge(&mut self, descriptor: &str, other: NpmDependencyDeclaration) {
        self.nonregistry |= other.nonregistry;
        if let Some(specification) = other.nonregistry_specification {
            self.nonregistry_specifications
                .insert(descriptor.to_owned(), specification);
        }
        if let Some(identity) = other.registry_identity {
            self.registry_identities
                .insert(descriptor.to_owned(), identity);
        }
        if let Some(constraint) = other.registry_constraint {
            self.registry_constraints
                .insert(descriptor.to_owned(), constraint);
        }
    }
}

#[derive(Default)]
pub(crate) struct NpmLockDeclarations {
    pub(crate) by_install_location: HashMap<String, NpmDependencyDeclarations>,
    pub(crate) direct_locations: BTreeSet<String>,
    pub(crate) reachable_locations: BTreeSet<String>,
}

impl NpmLockDeclarations {
    pub(crate) fn selected(&self, install_location: &str) -> Option<&NpmDependencyDeclarations> {
        self.by_install_location.get(install_location)
    }

    pub(crate) fn directness(&self, install_location: &str) -> Option<bool> {
        if self.direct_locations.contains(install_location) {
            Some(true)
        } else if self.reachable_locations.contains(install_location) {
            Some(false)
        } else {
            None
        }
    }
}

pub(crate) fn npm_dependency_install_location<'a>(
    descriptor: &str,
    name: &str,
    package_entries: &'a serde_json::Map<String, Json>,
) -> Option<&'a str> {
    let mut segments = if descriptor.is_empty() {
        Vec::new()
    } else {
        let segments = descriptor.split('/').collect::<Vec<_>>();
        if segments.iter().any(|segment| segment.is_empty()) {
            return None;
        }
        segments
    };

    loop {
        if segments.last().copied() != Some("node_modules") {
            let candidate = if segments.is_empty() {
                format!("node_modules/{name}")
            } else {
                format!("{}/node_modules/{name}", segments.join("/"))
            };
            if let Some((location, _)) = package_entries.get_key_value(&candidate) {
                return Some(location);
            }
        }
        segments.pop()?;
    }
}
