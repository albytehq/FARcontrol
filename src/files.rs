use crate::error::ApiError;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

/// File-operation guard (ADR-0009): every path is canonicalized and MUST stay
/// under `root` (default $HOME). Fail-closed: any resolution failure is a 4xx,
/// never a fallback.
fn expand(root: &Path, input: &str) -> PathBuf {
    let p = Path::new(input);
    if input == "~" {
        return root.to_path_buf();
    }
    if let Some(rest) = input.strip_prefix("~/") {
        return root.join(rest);
    }
    if let Some(rest) = input.strip_prefix('~') {
        return root.join(rest);
    }
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    }
}

fn guard_root(root: &Path, c: &Path) -> Result<(), ApiError> {
    if c.starts_with(root) {
        Ok(())
    } else {
        Err(ApiError::forbidden(
            "path_outside_root",
            format!("path resolves outside the allowed root ({})", root.display()),
        ))
    }
}

/// Resolve an EXISTING path (read/list) — symlinks are followed, then guarded.
pub fn resolve_existing(root: &Path, input: &str) -> Result<PathBuf, ApiError> {
    let p = expand(root, input);
    let c = fs::canonicalize(&p)
        .map_err(|_| ApiError::not_found("path_not_found", format!("path does not exist: {input}")))?;
    guard_root(root, &c)?;
    Ok(c)
}

/// Resolve a WRITE target. Existing target → canonicalize + guard. New target →
/// canonicalize the parent (must exist) + guard, then require a normal file name.
pub fn resolve_write(root: &Path, input: &str) -> Result<PathBuf, ApiError> {
    let p = expand(root, input);
    match fs::symlink_metadata(&p) {
        Ok(md) => {
            if md.is_dir() {
                return Err(ApiError::bad_request("invalid_path", "target is a directory"));
            }
            let c = fs::canonicalize(&p)
                .map_err(|_| ApiError::bad_request("invalid_path", "cannot resolve target (dangling symlink?)"))?;
            guard_root(root, &c)?;
            Ok(c)
        }
        Err(_) => {
            let parent = p
                .parent()
                .ok_or_else(|| ApiError::bad_request("invalid_path", "path has no parent directory"))?;
            let cparent = fs::canonicalize(parent).map_err(|_| {
                ApiError::bad_request("invalid_path", format!("parent directory does not exist: {}", parent.display()))
            })?;
            guard_root(root, &cparent)?;
            let name = p
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| ApiError::bad_request("invalid_path", "invalid file name"))?;
            if name == "." || name == ".." {
                return Err(ApiError::bad_request("invalid_path", "invalid file name"));
            }
            Ok(cparent.join(name))
        }
    }
}

pub fn read(root: &Path, input: &str, max: usize) -> Result<(PathBuf, Vec<u8>), ApiError> {
    let c = resolve_existing(root, input)?;
    let md = fs::metadata(&c).map_err(|_| ApiError::not_found("path_not_found", "cannot stat path"))?;
    if md.is_dir() {
        return Err(ApiError::bad_request("invalid_path", "path is a directory — use list instead"));
    }
    if md.len() as usize > max {
        return Err(ApiError::too_large(
            "file_too_large",
            format!("file is {} bytes, policy maximum is {}", md.len(), max),
        ));
    }
    let data = fs::read(&c).map_err(|e| ApiError::internal(format!("read failed: {e}")))?;
    Ok((c, data))
}

pub fn write(root: &Path, input: &str, data: &[u8], append: bool) -> Result<(PathBuf, u64), ApiError> {
    let c = resolve_write(root, input)?;
    if append {
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&c)
            .map_err(|e| ApiError::internal(format!("open failed: {e}")))?;
        f.write_all(data).map_err(|e| ApiError::internal(format!("write failed: {e}")))?;
    } else {
        fs::write(&c, data).map_err(|e| ApiError::internal(format!("write failed: {e}")))?;
    }
    Ok((c, data.len() as u64))
}

#[derive(Debug, Serialize)]
pub struct ListEntry {
    pub name: String,
    pub kind: &'static str,
    pub size: Option<u64>,
}

pub fn list(root: &Path, input: &str, max: usize) -> Result<(PathBuf, Vec<ListEntry>, bool), ApiError> {
    let c = resolve_existing(root, input)?;
    if !c.is_dir() {
        return Err(ApiError::bad_request("invalid_path", "path is not a directory"));
    }
    let mut entries: Vec<ListEntry> = Vec::new();
    let mut truncated = false;
    let rd = fs::read_dir(&c).map_err(|e| ApiError::internal(format!("read_dir failed: {e}")))?;
    for entry in rd {
        if entries.len() >= max {
            truncated = true;
            break;
        }
        let entry = entry.map_err(|e| ApiError::internal(format!("readdir entry failed: {e}")))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let ft = entry.file_type().map_err(|e| ApiError::internal(format!("filetype failed: {e}")))?;
        let kind = if ft.is_dir() {
            "dir"
        } else if ft.is_file() {
            "file"
        } else if ft.is_symlink() {
            "symlink"
        } else {
            "other"
        };
        let size = if ft.is_file() { entry.metadata().ok().map(|m| m.len()) } else { None };
        entries.push(ListEntry { name, kind, size });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok((c, entries, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("farcontrol-files-{}", crate::crypto::gen_nonce()));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn expansion_forms() {
        let root = Path::new("/home/user");
        assert_eq!(expand(root, "~"), PathBuf::from("/home/user"));
        assert_eq!(expand(root, "~/docs/a.txt"), PathBuf::from("/home/user/docs/a.txt"));
        assert_eq!(expand(root, "rel.txt"), PathBuf::from("/home/user/rel.txt"));
        assert_eq!(expand(root, "/abs/path"), PathBuf::from("/abs/path"));
    }

    #[test]
    fn read_write_roundtrip_and_guards() {
        let t = TempDir::new();
        let root = t.path();
        // write a new file via relative path
        let (p, n) = write(root, "agent-file.txt", b"farcontrol e2e", false).unwrap();
        assert_eq!(n, 14);
        assert!(p.starts_with(root));
        // read it back via ~ form
        let (p2, data) = read(root, "~/agent-file.txt", 1024).unwrap();
        assert_eq!(data, b"farcontrol e2e");
        assert_eq!(p, p2);
        // append
        let (_, n2) = write(root, "agent-file.txt", b"!", true).unwrap();
        assert_eq!(n2, 1);
        let (_, data3) = read(root, "agent-file.txt", 1024).unwrap();
        assert_eq!(data3, b"farcontrol e2e!");
    }

    #[test]
    fn escape_rejected() {
        let t = TempDir::new();
        let root = t.path();
        // symlink pointing outside
        let outside = std::env::temp_dir().join(format!("farcontrol-outside-{}", crate::crypto::gen_nonce()));
        std::fs::write(&outside, b"secret").unwrap();
        let link = root.join("escape-link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let err = read(root, "escape-link", 100).unwrap_err();
        assert_eq!(err.code, "path_outside_root");
        // absolute path outside root
        let err2 = read(root, "/etc/hostname", 100).unwrap_err();
        assert_eq!(err2.code, "path_outside_root");
        // ../ escape
        let err3 = read(root, "../../../etc/hostname", 100).unwrap_err();
        assert!(err3.code == "path_outside_root" || err3.code == "path_not_found");
        let _ = std::fs::remove_file(&outside);
    }

    #[test]
    fn write_requires_existing_parent() {
        let t = TempDir::new();
        let err = write(t.path(), "no/such/dir/file.txt", b"x", false).unwrap_err();
        assert_eq!(err.code, "invalid_path");
    }

    #[test]
    fn list_works() {
        let t = TempDir::new();
        write(t.path(), "b.txt", b"1", false).unwrap();
        write(t.path(), "a.txt", b"1", false).unwrap();
        std::fs::create_dir(t.path().join("sub")).unwrap();
        let (_, entries, truncated) = list(t.path(), "~", 100).unwrap();
        assert!(!truncated);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a.txt", "b.txt", "sub"]);
        assert!(entries.iter().find(|e| e.name == "sub").unwrap().kind == "dir");
    }
}
