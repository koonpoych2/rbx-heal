use std::{
    ffi::OsString,
    fs,
    path::{Component, Path, PathBuf},
};
use thiserror::Error;

/// A source path that has been canonicalized and proven to live below the
/// selected project root.  The absolute form is used only for local I/O;
/// the relative form is the one exposed in findings and metadata.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ProjectPath {
    absolute: PathBuf,
    relative: String,
}

impl ProjectPath {
    pub fn absolute(&self) -> &Path {
        &self.absolute
    }

    pub fn relative(&self) -> &str {
        &self.relative
    }

    pub fn into_absolute(self) -> PathBuf {
        self.absolute
    }
}

#[derive(Debug, Error)]
pub enum PathError {
    #[error("path must be relative to the project root: {path}")]
    NotRelative { path: PathBuf },
    #[error("path escapes the project root: {path}")]
    OutsideRoot { path: PathBuf },
    #[error("path does not exist: {path}")]
    Missing { path: PathBuf },
    #[error("path is not a regular file: {path}")]
    NotFile { path: PathBuf },
    #[error("path is not valid UTF-8: {path}")]
    NonUtf8 { path: PathBuf },
    #[error("path uses a non-portable `\\` separator: {path}")]
    NonPortableSeparator { path: PathBuf },
    #[error("could not canonicalize {path}: {source}")]
    Canonicalize {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("project root is not a directory: {path}")]
    RootNotDirectory { path: PathBuf },
}

/// Canonicalize a project root once at the CLI boundary.  All later path
/// checks compare against this exact root rather than the process cwd.
pub fn canonical_project_root(path: &Path) -> Result<PathBuf, PathError> {
    let root = fs::canonicalize(path).map_err(|source| PathError::Canonicalize {
        path: path.to_path_buf(),
        source,
    })?;
    if !root.is_dir() {
        return Err(PathError::RootNotDirectory { path: root });
    }
    Ok(root)
}

/// Reject lexical escapes before joining a user/config supplied path to the
/// project root.  This is deliberately stricter than merely canonicalizing:
/// a path that contains `..` or a drive/prefix is not accepted as a project
/// relative input even if it eventually resolves inside the root.
pub fn validate_relative_input(path: &Path) -> Result<(), PathError> {
    if path.is_absolute()
        || looks_like_windows_absolute(path)
        || path
            .to_str()
            .is_some_and(|value| value.starts_with(['/', '\\']))
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
        || path
            .to_str()
            .is_some_and(|value| value.split(['/', '\\']).any(|part| part == ".."))
    {
        return Err(PathError::NotRelative {
            path: path.to_path_buf(),
        });
    }
    #[cfg(not(windows))]
    if path.to_str().is_some_and(|value| value.contains('\\')) {
        return Err(PathError::NonPortableSeparator {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn looks_like_windows_absolute(path: &Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    let bytes = value.as_bytes();
    // Reject drive-qualified and UNC spellings even when a Windows path is
    // supplied to a Unix build.  Treating one of these as a literal filename
    // would be safe locally but would make a config non-portable and obscure
    // the user's intent.
    value.starts_with("\\\\")
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
}

/// Validate an existing path and return both its canonical absolute and safe
/// relative forms.  Symlinks/junctions are allowed only when their resolved
/// target remains inside the root.
pub fn validate_existing_path(project_root: &Path, path: &Path) -> Result<ProjectPath, PathError> {
    let absolute = fs::canonicalize(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            PathError::Missing {
                path: path.to_path_buf(),
            }
        } else {
            PathError::Canonicalize {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    if !is_within(project_root, &absolute) {
        return Err(PathError::OutsideRoot { path: absolute });
    }
    let relative = relative_utf8(project_root, &absolute)?;
    Ok(ProjectPath { absolute, relative })
}

pub fn validate_existing_file(project_root: &Path, path: &Path) -> Result<ProjectPath, PathError> {
    let validated = validate_existing_path(project_root, path)?;
    if !validated.absolute.is_file() {
        return Err(PathError::NotFile {
            path: validated.absolute,
        });
    }
    Ok(validated)
}

/// Build a safe source path from a finding's relative JSON path.
pub fn validate_finding_file(
    project_root: &Path,
    relative: &Path,
) -> Result<ProjectPath, PathError> {
    validate_relative_input(relative)?;
    validate_existing_file(project_root, &project_root.join(relative))
}

pub fn relative_utf8(project_root: &Path, path: &Path) -> Result<String, PathError> {
    let relative = path.strip_prefix(project_root).ok().map(Path::to_path_buf);
    #[cfg(windows)]
    let relative = relative.or_else(|| case_insensitive_relative(project_root, path));
    let relative = relative.ok_or_else(|| PathError::OutsideRoot {
        path: path.to_path_buf(),
    })?;
    let relative = relative.to_str().ok_or_else(|| PathError::NonUtf8 {
        path: path.to_path_buf(),
    })?;
    // Windows uses a backslash as its native separator, while Unix permits a
    // literal backslash in a filename.  Normalize separators only on Windows;
    // otherwise a perfectly valid Unix filename such as `a\\b.luau` would be
    // serialized as a different path and could no longer be reopened safely.
    #[cfg(windows)]
    {
        Ok(relative.replace('\\', "/"))
    }
    #[cfg(not(windows))]
    {
        // A literal backslash is legal in a Unix filename, but it cannot be
        // represented as the portable `/` JSON path used by reports,
        // baselines, and verifier argv. Fail closed instead of emitting a
        // path that would resolve to a different file on another platform.
        if relative.contains('\\') {
            return Err(PathError::NonPortableSeparator {
                path: path.to_path_buf(),
            });
        }
        Ok(relative.to_owned())
    }
}

fn is_within(root: &Path, candidate: &Path) -> bool {
    #[cfg(windows)]
    {
        let root = root.to_string_lossy().to_lowercase();
        let candidate = candidate.to_string_lossy().to_lowercase();
        candidate == root
            || candidate
                .strip_prefix(&root)
                .is_some_and(|suffix| suffix.starts_with('\\') || suffix.starts_with('/'))
    }
    #[cfg(not(windows))]
    {
        candidate == root
            || candidate
                .strip_prefix(root)
                .is_ok_and(|suffix| !suffix.as_os_str().is_empty())
    }
}

/// Relative path fallback for Windows paths whose canonical spelling differs
/// only by case.  Kept private because callers should normally use
/// `relative_utf8`, which receives canonical paths produced from one root.
#[allow(dead_code)]
fn case_insensitive_relative(root: &Path, candidate: &Path) -> Option<PathBuf> {
    let root_components = root.components().collect::<Vec<_>>();
    let candidate_components = candidate.components().collect::<Vec<_>>();
    if candidate_components.len() < root_components.len() {
        return None;
    }
    for (root_component, candidate_component) in
        root_components.iter().zip(candidate_components.iter())
    {
        if root_component.as_os_str().to_string_lossy().to_lowercase()
            != candidate_component
                .as_os_str()
                .to_string_lossy()
                .to_lowercase()
        {
            return None;
        }
    }
    let mut relative = PathBuf::new();
    for component in candidate_components.into_iter().skip(root_components.len()) {
        let value: OsString = component.as_os_str().to_os_string();
        relative.push(value);
    }
    Some(relative)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn rejects_absolute_and_parent_inputs() {
        assert!(matches!(
            validate_relative_input(Path::new("../outside")),
            Err(PathError::NotRelative { .. })
        ));
        #[cfg(not(windows))]
        assert!(matches!(
            validate_relative_input(Path::new("/outside")),
            Err(PathError::NotRelative { .. })
        ));
        #[cfg(windows)]
        assert!(matches!(
            validate_relative_input(Path::new("C:/outside")),
            Err(PathError::NotRelative { .. })
        ));
        #[cfg(not(windows))]
        assert!(matches!(
            validate_relative_input(Path::new(r"C:\outside")),
            Err(PathError::NotRelative { .. })
        ));
        #[cfg(not(windows))]
        assert!(matches!(
            validate_relative_input(Path::new(r"..\outside")),
            Err(PathError::NotRelative { .. })
        ));
    }

    #[test]
    fn canonical_file_has_relative_utf8_form() {
        let dir = tempdir().unwrap();
        let root = canonical_project_root(dir.path()).unwrap();
        let source = root.join("space ☃/é.luau");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(&source, "return 1\n").unwrap();
        let project_path = validate_existing_file(&root, &source).unwrap();
        assert_eq!(project_path.relative(), "space ☃/é.luau");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_literal_backslash_in_portable_relative_path() {
        let dir = tempdir().unwrap();
        let root = canonical_project_root(dir.path()).unwrap();
        let source = root.join("a\\b.luau");
        fs::write(&source, "return 1\n").unwrap();
        assert!(matches!(
            validate_existing_file(&root, &source),
            Err(PathError::NonPortableSeparator { .. })
        ));
    }

    #[test]
    fn rejects_existing_file_outside_root() {
        let root_dir = tempdir().unwrap();
        let outside_dir = tempdir().unwrap();
        let root = canonical_project_root(root_dir.path()).unwrap();
        let outside = outside_dir.path().join("outside.luau");
        fs::write(&outside, "return 1\n").unwrap();
        assert!(matches!(
            validate_existing_file(&root, &outside),
            Err(PathError::OutsideRoot { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_sibling_path_with_a_shared_string_prefix() {
        let parent = tempdir().unwrap();
        let root_dir = parent.path().join("project");
        let sibling_dir = parent.path().join("project-other");
        fs::create_dir_all(&root_dir).unwrap();
        fs::create_dir_all(&sibling_dir).unwrap();
        let root = canonical_project_root(&root_dir).unwrap();
        let outside = sibling_dir.join("outside.luau");
        fs::write(&outside, "return 1\n").unwrap();
        assert!(matches!(
            validate_existing_file(&root, &outside),
            Err(PathError::OutsideRoot { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_that_escapes_project_root() {
        use std::os::unix::fs::symlink;
        let root_dir = tempdir().unwrap();
        let outside_dir = tempdir().unwrap();
        let root = canonical_project_root(root_dir.path()).unwrap();
        let outside = outside_dir.path().join("secret.luau");
        fs::write(&outside, "return 1\n").unwrap();
        let link = root.join("linked.luau");
        symlink(&outside, &link).unwrap();
        assert!(matches!(
            validate_existing_file(&root, &link),
            Err(PathError::OutsideRoot { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn allows_in_root_symlink_but_returns_canonical_relative_path() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let root = canonical_project_root(dir.path()).unwrap();
        let target = root.join("real.luau");
        fs::write(&target, "return 1\n").unwrap();
        let link = root.join("alias.luau");
        symlink(&target, &link).unwrap();
        let validated = validate_existing_file(&root, &link).unwrap();
        assert_eq!(validated.relative(), "real.luau");
    }
}
