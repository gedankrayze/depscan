use super::*;

#[derive(Default)]
pub(crate) struct NodeDirectDependencies {
    pub(crate) all: HashSet<String>,
    pub(crate) complete: bool,
}

impl NodeDirectDependencies {
    pub(crate) fn directness(&self, name: &str) -> Option<bool> {
        self.all
            .contains(name)
            .then_some(true)
            .or_else(|| self.complete.then_some(false))
    }
}

pub(crate) struct NodeProjectDependency {
    pub(crate) name: String,
    pub(crate) constraint: String,
    pub(crate) development: bool,
}

#[derive(Default)]
pub(crate) struct NodeProjectDependencies {
    pub(crate) declarations: Vec<NodeProjectDependency>,
    pub(crate) complete: bool,
}

pub(crate) fn append_node_manifest_dependencies(
    path: &Path,
    value: &Json,
    dependencies: &mut NodeProjectDependencies,
) -> Result<(), ParseError> {
    dependencies
        .declarations
        .extend(
            parse_package_json_value(path, value)?
                .into_iter()
                .map(|package| {
                    let constraint = package
                        .manifest_constraint
                        .expect("package.json dependency has a manifest constraint")
                        .raw()
                        .to_owned();
                    NodeProjectDependency {
                        name: package.display_name,
                        constraint,
                        development: package.dev,
                    }
                }),
        );
    Ok(())
}

pub(crate) fn node_project_dependencies(root: &Path) -> NodeProjectDependencies {
    let root_manifest = root.join("package.json");
    let Ok(root_value) = read_validated_root_package_json(&root_manifest) else {
        return NodeProjectDependencies::default();
    };

    let mut dependencies = NodeProjectDependencies::default();
    if append_node_manifest_dependencies(&root_manifest, &root_value, &mut dependencies).is_err() {
        return dependencies;
    }

    let Ok(manifests) = workspace_manifests(&root_manifest, &root_value) else {
        return dependencies;
    };
    let mut complete = true;
    for manifest in manifests {
        if manifest == root_manifest {
            continue;
        }
        let parsed = read_package_json(&manifest).and_then(|value| {
            append_node_manifest_dependencies(&manifest, &value, &mut dependencies)
        });
        if parsed.is_err() {
            complete = false;
        }
    }
    dependencies.complete = complete;
    dependencies
}

pub(crate) fn node_direct_dependencies(root: &Path) -> NodeDirectDependencies {
    let dependencies = node_project_dependencies(root);
    let mut direct = NodeDirectDependencies {
        complete: dependencies.complete,
        ..NodeDirectDependencies::default()
    };
    for declaration in dependencies.declarations {
        direct.all.insert(declaration.name);
    }
    direct
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct YarnDirectness {
    pub(crate) production: bool,
    pub(crate) development: bool,
}

#[derive(Clone)]
pub(crate) struct YarnDirectSelector {
    pub(crate) constraint: String,
    pub(crate) directness: YarnDirectness,
    pub(crate) matching_entries: usize,
}

#[derive(Default)]
pub(crate) struct YarnDirectDependencies {
    pub(crate) by_name: HashMap<String, Vec<YarnDirectSelector>>,
}

pub(crate) fn yarn_direct_dependencies(root: &Path) -> YarnDirectDependencies {
    let dependencies = node_project_dependencies(root);
    let mut direct = YarnDirectDependencies::default();
    for declaration in dependencies.declarations {
        let selectors = direct.by_name.entry(declaration.name).or_default();
        let selector_index = selectors
            .iter()
            .position(|selector| selector.constraint == declaration.constraint)
            .unwrap_or_else(|| {
                selectors.push(YarnDirectSelector {
                    constraint: declaration.constraint,
                    directness: YarnDirectness::default(),
                    matching_entries: 0,
                });
                selectors.len() - 1
            });
        let flags = &mut selectors[selector_index].directness;
        if declaration.development {
            flags.development = true;
        } else {
            flags.production = true;
        }
    }
    direct
}
