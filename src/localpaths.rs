//! Refuse Windows remote drives and filesystem redirections before reads.
//! Ported from zero-breach scan/adint_scan/localpaths.py (Apache-2.0).
//!
//! Checks are conservative and inspect each component without following it,
//! so a reparse point is inspected rather than traversed. POSIX network mounts
//! cannot always be distinguished from local paths here. This is not a sandbox
//! against concurrent filesystem changes.

use std::path::{Path, PathBuf};

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

/// `FILE_ATTRIBUTE_REPARSE_POINT` (the `0x400` mask the Python checks via
/// `st_file_attributes`).
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

fn is_symlink_or_reparse(md: &std::fs::Metadata) -> bool {
    if md.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    if md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return true;
    }
    #[cfg(not(windows))]
    let _ = md;
    false
}

/// Select a local temporary directory without tempfile's write-probing
/// fallback, so a redirected TEMP cannot send snapshots somewhere unsafe.
/// Ported from `local_temp_dir`.
pub fn local_temp_dir() -> Result<PathBuf, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    for key in ["TMPDIR", "TEMP", "TMP"] {
        if let Ok(v) = std::env::var(key) {
            if !v.is_empty() {
                candidates.push(PathBuf::from(v));
            }
        }
    }
    if cfg!(windows) {
        for base in ["LOCALAPPDATA", "SystemRoot"] {
            if let Ok(v) = std::env::var(base) {
                if !v.is_empty() {
                    candidates.push(Path::new(&v).join("Temp"));
                }
            }
        }
    } else {
        candidates.extend(
            ["/tmp", "/var/tmp", "/private/tmp"]
                .iter()
                .map(PathBuf::from),
        );
    }
    for candidate in candidates {
        if path_problem(&candidate).is_none() && candidate.is_dir() {
            return Ok(candidate);
        }
    }
    Err("no safe local temporary directory is available".to_string())
}

/// Why a path cannot safely be inspected, or `None` if it may be opened.
///
/// A `None` result means "as far as these checks can tell, this is a local
/// path"; a genuinely absent artifact is also `None` (the caller handles
/// absence itself).
pub fn path_problem(path: &Path) -> Option<String> {
    let text = path.to_string_lossy();
    if !path.is_absolute() {
        return Some("relative path cannot be classified as local".to_string());
    }
    if text.replace('\\', "/").split('/').any(|part| part == "..") {
        return Some("parent-directory traversal cannot be classified as local".to_string());
    }

    #[cfg(windows)]
    if let Some(problem) = windows_drive_problem(&text) {
        return Some(problem);
    }

    // Walk each component without following it.
    let mut components: Vec<PathBuf> = {
        let mut v: Vec<PathBuf> = path.ancestors().map(Path::to_path_buf).collect();
        v.reverse();
        v
    };
    // The first entry is the filesystem root, which is never a link.
    components.remove(0);

    for (index, current) in components.iter().enumerate() {
        #[cfg(not(target_os = "macos"))]
        let _ = index;
        let info = match std::fs::symlink_metadata(current) {
            Ok(info) => info,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // The caller handles a genuinely absent artifact.
                return None;
            }
            Err(e) => {
                return Some(format!(
                    "cannot safely inspect {}: {}",
                    current.display(),
                    e
                ));
            }
        };
        if is_symlink_or_reparse(&info) {
            // macOS exposes its standard /var, /tmp and /etc directories
            // through root-owned aliases into /private. These exact system
            // aliases are safe to validate lexically; arbitrary user links
            // remain refused. read_link reads the link itself and does not
            // traverse its target.
            #[cfg(target_os = "macos")]
            if let Some(canonical) = macos_system_alias(current, &info) {
                let mut canonical_path = PathBuf::from(canonical);
                for part in path.components().skip(index + 1 + 1) {
                    canonical_path.push(part);
                }
                return path_problem(&canonical_path);
            }
            return Some(format!(
                "symlink or reparse point was not followed: {}",
                current.display()
            ));
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn macos_system_alias(current: &Path, info: &std::fs::Metadata) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let text = current.to_string_lossy();
    let (alias, target) = match text.as_ref() {
        "/var" => ("/var", "/private/var"),
        "/tmp" => ("/tmp", "/private/tmp"),
        "/etc" => ("/etc", "/private/etc"),
        _ => return None,
    };
    if !info.file_type().is_symlink() || info.uid() != 0 {
        return None;
    }
    let link = std::fs::read_link(current).ok()?;
    let link_text = link.to_string_lossy().into_owned();
    // Apple's links commonly use 'private/var', relative to '/'.
    if link_text == target || link_text == target.trim_start_matches('/') {
        Some(target.to_string())
    } else {
        // A root-owned link at an alias path that does not point where Apple
        // points it is NOT a system alias.
        let _ = alias;
        None
    }
}

#[cfg(windows)]
fn windows_drive_problem(text: &str) -> Option<String> {
    let s = text.replace('/', "\\");
    if s.starts_with("\\\\") {
        return Some("UNC or device path was not opened".to_string());
    }
    let mut chars = s.chars();
    let drive_ok = match (chars.next(), chars.next()) {
        (Some(d), Some(':')) => {
            let rest: String = chars.collect();
            d.is_ascii_alphabetic()
                && (rest.is_empty() || rest.starts_with('\\') || rest.starts_with('/'))
        }
        _ => false,
    };
    if !drive_ok {
        return Some("path does not name an absolute local drive".to_string());
    }
    let drive = format!("{}:\\", s.chars().next().unwrap());
    let kind = drive_type(&drive);
    // 2 removable, 3 fixed, 5 CD-ROM, 6 RAM disk — the local kinds.
    if !matches!(kind, 2 | 3 | 5 | 6) {
        return Some("drive is remote or its locality is unknown".to_string());
    }
    None
}

#[cfg(windows)]
fn drive_type(drive: &str) -> u32 {
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    let wide: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { GetDriveTypeW(wide.as_ptr()) }
}

/// One refused filesystem entry, delivered to the walk's error handler.
#[derive(Clone, Debug)]
pub struct WalkProblem {
    pub path: PathBuf,
    pub reason: String,
}

/// What a directory walk reports. Ported from `walk_local`'s two callbacks:
/// refused entries go to [`WalkHandler::onerror`] — an unreadable subtree must
/// never vanish silently — and each successfully-read directory delivers its
/// regular files to [`WalkHandler::files`], in walk order.
pub trait WalkHandler {
    fn onerror(&mut self, problem: WalkProblem);
    fn files(&mut self, dir: &Path, files: &[PathBuf]);
}

/// Top-down walk that never classifies a link by following it.
///
/// `prune` decides, by directory name, which directories are not descended
/// into (the caller's `dirs[:] = [...]` filter upstream).
pub fn walk_local(root: &Path, prune: &dyn Fn(&str) -> bool, handler: &mut dyn WalkHandler) {
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(current) = pending.pop() {
        match std::fs::read_dir(&current) {
            Err(e) => {
                handler.onerror(WalkProblem {
                    path: current.clone(),
                    reason: format!("could not enumerate {}: {}", current.display(), e),
                });
                continue;
            }
            Ok(entries) => {
                let mut dirs: Vec<PathBuf> = Vec::new();
                let mut files: Vec<PathBuf> = Vec::new();
                for entry in entries {
                    let entry = match entry {
                        Ok(e) => e,
                        Err(e) => {
                            handler.onerror(WalkProblem {
                                path: current.clone(),
                                reason: format!("could not enumerate {}: {}", current.display(), e),
                            });
                            continue;
                        }
                    };
                    let path = entry.path();
                    let info = match entry.metadata() {
                        Ok(info) => info,
                        Err(e) => {
                            handler.onerror(WalkProblem {
                                path: path.clone(),
                                reason: format!("could not read {}: {}", path.display(), e),
                            });
                            continue;
                        }
                    };
                    if is_symlink_or_reparse(&info) {
                        handler.onerror(WalkProblem {
                            path: path.clone(),
                            reason: "symlink or reparse point was not followed".to_string(),
                        });
                        continue;
                    }
                    let ft = info.file_type();
                    if ft.is_dir() {
                        dirs.push(path);
                    } else if ft.is_file() {
                        files.push(path);
                    } else {
                        handler.onerror(WalkProblem {
                            path: path.clone(),
                            reason: "special filesystem entry was not opened".to_string(),
                        });
                    }
                }
                // Prune before descending, exactly as the caller's in-place
                // `dirs[:] = [...]` filter did.
                dirs.retain(|d| {
                    let name = d
                        .file_name()
                        .map(|n| n.to_string_lossy().to_lowercase())
                        .unwrap_or_default();
                    !prune(&name)
                });
                handler.files(&current, &files);
                // Pushed in reverse so the leftmost directory is walked first.
                for d in dirs.iter().rev() {
                    pending.push(d.clone());
                }
            }
        }
    }
}

/// Lexical normalisation mirroring `os.path.normpath` for the shapes this tool
/// produces (no `.` or `..` in the roots it builds, but never assume).
pub fn normpath(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    let windows = cfg!(windows);
    let sep = if windows { '\\' } else { '/' };
    let absolute = text.starts_with('/') || (windows && text.starts_with('\\'));
    let mut parts: Vec<String> = Vec::new();
    for part in text.split(['/', '\\']) {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            if !parts.is_empty() && parts.last().map(|p| p.as_str()) != Some("..") {
                parts.pop();
                continue;
            }
            if absolute {
                continue; // /.. is /
            }
        }
        parts.push(part.to_string());
    }
    let joined = parts.join(&sep.to_string());
    let prefix: String = if windows {
        // Keep a leading drive letter, if any.
        let mut c = text.chars();
        match (c.next(), c.next()) {
            (Some(d), Some(':')) if d.is_ascii_alphabetic() => format!("{}:\\", d),
            _ if absolute => "\\".to_string(),
            _ => String::new(),
        }
    } else if absolute {
        "/".to_string()
    } else {
        String::new()
    };
    let out = format!("{}{}", prefix, joined);
    if out.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(out)
    }
}

/// `os.path.normcase`: on Windows, lower-case and forward the separators to
/// backslashes; elsewhere, identity.
pub fn normcase(path: &Path) -> PathBuf {
    let text = path.to_string_lossy().into_owned();
    if cfg!(windows) {
        PathBuf::from(text.to_lowercase().replace('/', "\\"))
    } else {
        PathBuf::from(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths_are_refused() {
        assert_eq!(
            path_problem(Path::new("relative/path.json")),
            Some("relative path cannot be classified as local".to_string())
        );
    }

    #[test]
    fn traversal_is_refused() {
        assert_eq!(
            path_problem(Path::new("/tmp/../etc/passwd")),
            Some("parent-directory traversal cannot be classified as local".to_string())
        );
    }

    #[test]
    fn a_plain_tmp_file_is_local() {
        let dir = std::env::temp_dir().join("zb_localpaths_ok");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f.txt");
        std::fs::write(&p, b"x").unwrap();
        assert_eq!(path_problem(&p), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_symlink_is_refused() {
        let dir = std::env::temp_dir().join("zb_localpaths_link");
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("real.txt");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&target, &link).unwrap();
        assert!(path_problem(&link)
            .unwrap()
            .starts_with("symlink or reparse point was not followed"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn absent_artifact_is_not_a_problem() {
        let p = std::env::temp_dir().join("zb_localpaths_absent_definitely_not_here");
        assert_eq!(path_problem(&p), None);
    }

    #[cfg(windows)]
    #[test]
    fn unc_is_refused() {
        assert_eq!(
            path_problem(Path::new(r"\\server\share\x")),
            Some("UNC or device path was not opened".to_string())
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn a_windows_letter_is_not_a_posix_absolute_path() {
        assert_eq!(
            path_problem(Path::new(r"C:\Users\Public")),
            Some("relative path cannot be classified as local".to_string())
        );
    }

    #[test]
    fn walk_visits_files_and_refuses_links() {
        let dir = std::env::temp_dir().join("zb_walk_test");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::create_dir_all(dir.join("SkipMe")).unwrap();
        std::fs::write(dir.join("a.txt"), b"1").unwrap();
        std::fs::write(dir.join("sub").join("b.txt"), b"2").unwrap();
        std::fs::write(dir.join("SkipMe").join("c.txt"), b"3").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("a.txt"), dir.join("l.txt")).unwrap();

        let mut files: Vec<PathBuf> = Vec::new();
        let mut problems = 0;
        struct H<'a> {
            files: &'a mut Vec<PathBuf>,
            problems: &'a mut i32,
        }
        impl WalkHandler for H<'_> {
            fn onerror(&mut self, _p: WalkProblem) {
                *self.problems += 1;
            }
            fn files(&mut self, _d: &Path, fs: &[PathBuf]) {
                self.files.extend(fs.iter().cloned());
            }
        }
        let mut h = H {
            files: &mut files,
            problems: &mut problems,
        };
        walk_local(&dir, &|name: &str| name == "skipme", &mut h);
        let names: Vec<String> = files
            .iter()
            .map(|f| f.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"a.txt".to_string()));
        assert!(names.contains(&"b.txt".to_string()));
        assert!(!names.contains(&"c.txt".to_string()), "pruned dir skipped");
        assert_eq!(problems, 1, "the symlink is refused, not followed");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn normpath_collapses() {
        assert_eq!(
            normpath(Path::new("/tmp//a/./b")),
            PathBuf::from("/tmp/a/b")
        );
        assert_eq!(normpath(Path::new("a/b/../c")), PathBuf::from("a/c"));
    }
}
