use super::*;

pub(crate) fn cargo_member_edge_scopes(
    member: &CargoProjectPackageId,
    dependencies: &[usize],
    nodes: &[CargoLockNode],
    declarations: &[CargoDeclaration],
) -> BTreeMap<usize, CargoScope> {
    let declarations = declarations
        .iter()
        .filter(|declaration| declaration.declaring_package == *member)
        .collect::<Vec<_>>();
    let mut exact = BTreeMap::<usize, Vec<bool>>::new();
    let mut possible = BTreeMap::<usize, Vec<bool>>::new();
    for declaration in declarations {
        let exact_targets = dependencies
            .iter()
            .copied()
            .filter(|target| {
                cargo_declaration_target_strength(declaration, &nodes[*target].id)
                    == CargoDeclarationTargetStrength::Exact
            })
            .collect::<Vec<_>>();
        if exact_targets.len() == 1 {
            exact
                .entry(exact_targets[0])
                .or_default()
                .push(declaration.dev);
            continue;
        }
        let possible_targets = dependencies
            .iter()
            .copied()
            .filter(|target| {
                cargo_declaration_target_strength(declaration, &nodes[*target].id)
                    != CargoDeclarationTargetStrength::None
            })
            .collect::<Vec<_>>();
        for target in possible_targets {
            possible.entry(target).or_default().push(declaration.dev);
        }
    }
    dependencies
        .iter()
        .copied()
        .map(|target| {
            if nodes[target].replacement.is_some() {
                return (target, CargoScope::Unknown);
            }
            let exact = exact.get(&target).map(Vec::as_slice).unwrap_or(&[]);
            let possible = possible.get(&target).map(Vec::as_slice).unwrap_or(&[]);
            let scope = if exact.iter().any(|dev| !dev) {
                CargoScope::Production
            } else if possible.iter().any(|dev| !dev) {
                CargoScope::Unknown
            } else if exact.iter().any(|dev| *dev) {
                CargoScope::Development
            } else {
                CargoScope::Unknown
            };
            (target, scope)
        })
        .collect()
}

pub(crate) fn cargo_reachable(
    seeds: impl IntoIterator<Item = usize>,
    nodes: &[CargoLockNode],
    members: &BTreeSet<usize>,
) -> BTreeSet<usize> {
    let mut reached = BTreeSet::new();
    let mut pending = VecDeque::new();
    for seed in seeds {
        if reached.insert(seed) {
            pending.push_back(seed);
        }
    }
    while let Some(index) = pending.pop_front() {
        if members.contains(&index) {
            continue;
        }
        let dependencies = nodes[index]
            .replacement
            .iter()
            .chain(nodes[index].dependencies.iter());
        for dependency in dependencies {
            if reached.insert(*dependency) {
                pending.push_back(*dependency);
            }
        }
    }
    reached
}

pub(crate) fn parse_cargo_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let value: Toml = toml::from_str(&text).map_err(|e| invalid(path, e))?;
    let document = value.as_table().ok_or_else(|| {
        invalid(
            path,
            "detected a non-table TOML document; expected a Cargo.lock table",
        )
    })?;
    let lockfile_version = match document.get("version") {
        Some(version) => version.as_integer().ok_or_else(|| {
            invalid(
                path,
                "detected Cargo.lock with a non-integer version; expected lockfile version 1 through 4",
            )
        })?,
        None => 1,
    };
    if !(1..=4).contains(&lockfile_version) {
        return Err(invalid(
            path,
            format!(
                "detected unsupported Cargo.lock version {lockfile_version}; expected version 1 through 4"
            ),
        ));
    }
    let package_entries: &[Toml] = match document.get("package") {
        Some(package_entries) => package_entries.as_array().map(Vec::as_slice).ok_or_else(|| {
            invalid(
                path,
                format!(
                    "detected Cargo.lock version {lockfile_version} without a package array; expected resolved package entries"
                ),
            )
        })?,
        None if lockfile_version == 1 && document.contains_key("root") => &[],
        None => {
            return Err(invalid(
                path,
                format!(
                    "detected Cargo.lock version {lockfile_version} without a package array; expected resolved package entries"
                ),
            ));
        }
    };
    let mut raw_nodes = Vec::new();
    for (index, item) in package_entries.iter().enumerate() {
        let item = item.as_table().ok_or_else(|| {
            invalid(
                path,
                format!("Cargo.lock package entry {index} must be a table"),
            )
        })?;
        raw_nodes.push(cargo_lock_node(
            path,
            &format!("Cargo.lock package entry {index}"),
            item,
            true,
        )?);
    }
    if let Some(root) = document.get("root") {
        if lockfile_version != 1 {
            return Err(invalid(
                path,
                "Cargo.lock [root] is supported only for version 1 lockfiles",
            ));
        }
        let root = root
            .as_table()
            .ok_or_else(|| invalid(path, "Cargo.lock [root] must be a table"))?;
        raw_nodes.push(cargo_lock_node(
            path,
            "Cargo.lock legacy root",
            root,
            false,
        )?);
    }

    let mut identities = BTreeMap::new();
    for (index, node) in raw_nodes.iter().enumerate() {
        if let Some(previous) = identities.insert(node.id.clone(), index) {
            return Err(invalid(
                path,
                format!(
                    "Cargo.lock repeats exact package identity {} {} at entries {previous} and {index}",
                    node.id.name, node.id.version
                ),
            ));
        }
    }

    let mut nodes = Vec::with_capacity(raw_nodes.len());
    for (raw_index, raw) in raw_nodes.iter().enumerate() {
        let mut dependencies = BTreeSet::new();
        for dependency in &raw.dependency_references {
            let reference = parse_cargo_lock_reference(path, &raw.context, dependency)?;
            let dependency = resolve_cargo_lock_reference(
                path,
                &raw.context,
                &reference,
                &raw_nodes,
                lockfile_version,
            )?;
            if dependency == raw_index {
                return Err(invalid(
                    path,
                    format!("{} cannot depend on itself", raw.context),
                ));
            }
            dependencies.insert(dependency);
        }
        let replacement = raw
            .replacement_reference
            .as_deref()
            .map(|replacement| {
                let reference = parse_cargo_lock_reference(path, &raw.context, replacement)?;
                resolve_cargo_lock_reference(
                    path,
                    &raw.context,
                    &reference,
                    &raw_nodes,
                    lockfile_version,
                )
            })
            .transpose()?;
        if let Some(replacement) = replacement {
            let target = &raw_nodes[replacement];
            if target.id == raw.id {
                return Err(invalid(
                    path,
                    format!("{} cannot replace itself", raw.context),
                ));
            }
            if target.id.name != raw.id.name || target.id.version != raw.id.version {
                return Err(invalid(
                    path,
                    format!(
                        "{} replacement must have the same package name and version",
                        raw.context
                    ),
                ));
            }
            if target.replacement_reference.is_some() {
                return Err(invalid(
                    path,
                    format!(
                        "{} replacement target cannot itself define replace",
                        raw.context
                    ),
                ));
            }
        }
        nodes.push(CargoLockNode {
            id: raw.id.clone(),
            dependencies: dependencies.into_iter().collect(),
            replacement,
            emit: raw.emit,
        });
    }

    let mut direct = vec![false; nodes.len()];
    let mut direct_known = vec![false; nodes.len()];
    let mut dev = vec![false; nodes.len()];
    let mut dev_known = vec![false; nodes.len()];
    let manifest = path.parent().unwrap_or(Path::new(".")).join("Cargo.toml");
    if manifest.is_file() {
        let evidence = cargo_project_evidence(&manifest)?;
        let member_indices = evidence
            .packages
            .iter()
            .map(|member| {
                nodes.iter().position(|node| {
                    node.id.name == member.name
                        && node.id.version == member.version
                        && node.id.source.is_none()
                })
            })
            .collect::<Option<BTreeSet<_>>>();
        if let Some(member_indices) = member_indices {
            let mut direct_targets = BTreeSet::new();
            let mut production_seeds = member_indices.clone();
            let mut development_seeds = BTreeSet::new();
            let mut unknown_seeds = BTreeSet::new();
            for member_index in &member_indices {
                let member = CargoProjectPackageId {
                    name: nodes[*member_index].id.name.clone(),
                    version: nodes[*member_index].id.version.clone(),
                };
                let scopes = cargo_member_edge_scopes(
                    &member,
                    &nodes[*member_index].dependencies,
                    &nodes,
                    &evidence.declarations,
                );
                for target in &nodes[*member_index].dependencies {
                    direct_targets.insert(*target);
                    match scopes.get(target).copied().unwrap_or(CargoScope::Unknown) {
                        CargoScope::Production => {
                            production_seeds.insert(*target);
                        }
                        CargoScope::Development => {
                            development_seeds.insert(*target);
                        }
                        CargoScope::Unknown => {
                            unknown_seeds.insert(*target);
                        }
                    }
                }
            }

            let reachable =
                cargo_reachable(member_indices.iter().copied(), &nodes, &BTreeSet::new());
            let production =
                cargo_reachable(production_seeds.iter().copied(), &nodes, &member_indices);
            let development =
                cargo_reachable(development_seeds.iter().copied(), &nodes, &member_indices);
            let unknown = cargo_reachable(unknown_seeds.iter().copied(), &nodes, &member_indices);
            for index in reachable {
                direct[index] = direct_targets.contains(&index);
                direct_known[index] = true;
                if production.contains(&index) {
                    dev[index] = false;
                    dev_known[index] = true;
                } else if unknown.contains(&index) {
                    dev[index] = false;
                    dev_known[index] = false;
                } else if development.contains(&index) {
                    dev[index] = true;
                    dev_known[index] = true;
                }
            }
        }
    }

    let mut out = Vec::new();
    for (index, node) in nodes.into_iter().enumerate() {
        if !node.emit {
            continue;
        }
        let mut package = Package::new(
            Ecosystem::CratesIo,
            node.id.name,
            node.id.version,
            path.to_path_buf(),
        );
        package.direct = direct[index];
        package.direct_known = direct_known[index];
        package.dev = dev[index];
        package.dev_known = dev_known[index];
        package.enrichable =
            node.replacement.is_none() && node.id.source.as_deref() == Some(CARGO_CRATES_IO_SOURCE);
        out.push(package);
    }
    Ok(dedup(out))
}
pub(crate) fn parse_cargo_toml(path: &Path) -> Result<Vec<Package>, ParseError> {
    let mut packages = BTreeMap::new();
    for declaration in cargo_project_declarations(path)? {
        let Some(version) = declaration.dependency.version else {
            continue;
        };
        let mut package = Package::new(
            Ecosystem::CratesIo,
            declaration.dependency.package_name,
            version,
            declaration.declaring_manifest,
        );
        package.direct = true;
        package.dev = declaration.dev;
        package.enrichable = declaration.dependency.enrichable;
        let constraint = package.version.clone();
        package.set_manifest_constraint(constraint);
        let key = (package.key(), package.source_file.clone());
        packages
            .entry(key)
            .and_modify(|existing: &mut Package| {
                existing.dev &= package.dev;
                existing.enrichable |= package.enrichable;
            })
            .or_insert(package);
    }
    Ok(packages.into_values().collect())
}
