use crate::{
    config::Config,
    path::{
        canonical_project_root as canonicalize_root, relative_utf8, validate_existing_path,
        validate_relative_input, PathError,
    },
};
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("invalid glob `{pattern}`: {source}")]
    Glob {
        pattern: String,
        source: globset::Error,
    },
    #[error("could not inspect {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid project path: {0}")]
    Path(#[from] PathError),
}

fn build_set(patterns: &[String]) -> Result<GlobSet, DiscoveryError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = Glob::new(pattern).map_err(|source| DiscoveryError::Glob {
            pattern: pattern.clone(),
            source,
        })?;
        builder.add(glob);
    }
    builder.build().map_err(|source| DiscoveryError::Glob {
        pattern: "<set>".into(),
        source,
    })
}

pub fn discover_files(
    project_root: &Path,
    config: &Config,
    inputs: &[PathBuf],
) -> Result<Vec<PathBuf>, DiscoveryError> {
    let project_root = canonicalize_root(project_root)?;
    let include = build_set(&config.scan.include)?;
    let exclude = build_set(&config.scan.exclude)?;
    let roots = if inputs.is_empty() {
        if config.scan.roots.is_empty() {
            vec![project_root.clone()]
        } else {
            config
                .scan
                .roots
                .iter()
                .map(|root| {
                    validate_relative_input(Path::new(root))?;
                    let joined = project_root.join(root);
                    match std::fs::symlink_metadata(&joined) {
                        Ok(_) => Ok(Some(
                            validate_existing_path(&project_root, &joined)?.into_absolute(),
                        )),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                        Err(error) => Err(DiscoveryError::Io {
                            path: joined,
                            source: error,
                        }),
                    }
                })
                .collect::<Result<Vec<_>, DiscoveryError>>()?
                .into_iter()
                .flatten()
                .collect()
        }
    } else {
        inputs
            .iter()
            .map(|path| {
                validate_relative_input(path)?;
                let joined = project_root.join(path);
                match std::fs::symlink_metadata(&joined) {
                    Ok(_) => Ok(validate_existing_path(&project_root, &joined)?.into_absolute()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        Err(DiscoveryError::Path(PathError::Missing { path: joined }))
                    }
                    Err(error) => Err(DiscoveryError::Io {
                        path: joined,
                        source: error,
                    }),
                }
            })
            .collect::<Result<Vec<_>, DiscoveryError>>()?
    };

    let mut files = BTreeSet::new();
    for root in roots {
        if !root.exists() {
            continue;
        }
        let validated_root = validate_existing_path(&project_root, &root)?;
        let root = validated_root.into_absolute();
        if root.is_file() {
            if accepts(&project_root, &root, &include, &exclude)? {
                files.insert(root);
            }
            continue;
        }
        for entry in WalkDir::new(&root).follow_links(false).into_iter() {
            let entry = entry.map_err(|error| DiscoveryError::Io {
                path: root.clone(),
                source: error
                    .into_io_error()
                    .unwrap_or_else(|| std::io::Error::other("directory traversal failed")),
            })?;
            let path = entry.path();
            if entry.file_type().is_symlink() {
                // Do not silently ignore a reparse point that escapes the
                // project. Validate its resolved target even though the
                // walker deliberately does not follow links for traversal.
                validate_existing_path(&project_root, path)?;
                continue;
            }
            // Windows junctions can be reported as directories rather than
            // ordinary symlinks. Canonicalizing every directory entry keeps
            // those reparse points subject to the same containment check.
            if entry.file_type().is_dir() {
                validate_existing_path(&project_root, path)?;
            }
            if entry.file_type().is_file() {
                let validated = validate_existing_path(&project_root, path)?;
                let path = validated.into_absolute();
                if accepts(&project_root, &path, &include, &exclude)? {
                    files.insert(path);
                }
            }
        }
    }
    Ok(files.into_iter().collect())
}

fn accepts(
    project_root: &Path,
    path: &Path,
    include: &GlobSet,
    exclude: &GlobSet,
) -> Result<bool, DiscoveryError> {
    let relative = relative_utf8(project_root, path)?;
    let extension_ok = path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == "lua" || extension == "luau");
    Ok(extension_ok && include.is_match(&relative) && !exclude.is_match(&relative))
}

pub fn canonical_project_root(path: &Path) -> Result<PathBuf, DiscoveryError> {
    canonicalize_root(path).map_err(DiscoveryError::Path)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::Config;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn reports_non_utf8_source_path_instead_of_silently_skipping() {
        use std::os::unix::ffi::OsStringExt;
        let dir = tempdir().unwrap();
        let root = dir.path().join("src");
        fs::create_dir_all(&root).unwrap();
        let name = std::ffi::OsString::from_vec(vec![0x66, 0x80, 0x2e, 0x6c, 0x75, 0x61, 0x75]);
        fs::write(root.join(name), "return 1\n").unwrap();
        let error = discover_files(dir.path(), &Config::default(), &[]).unwrap_err();
        assert!(matches!(
            error,
            DiscoveryError::Path(PathError::NonUtf8 { .. })
        ));
    }

    #[test]
    fn rejects_nested_symlink_that_escapes_project_root() {
        use std::os::unix::fs::symlink;
        let project = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("outside.luau"), "return 1\n").unwrap();
        fs::create_dir_all(project.path().join("src")).unwrap();
        symlink(
            outside.path(),
            project.path().join("src").join("linked-folder"),
        )
        .unwrap();
        let error = discover_files(project.path(), &Config::default(), &[]).unwrap_err();
        assert!(matches!(
            error,
            DiscoveryError::Path(PathError::OutsideRoot { .. })
        ));
    }
}
