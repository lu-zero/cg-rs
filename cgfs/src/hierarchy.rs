//! Verified cgroup2 hierarchy and cgroup handles.
//!
//! Public mutating operations are rooted at a verified [`Hierarchy`] and use
//! descriptor-relative opens with no path, symlink, magic-link, or mount
//! crossing. A caller cannot pass an arbitrary absolute path to a mutating
//! operation.

use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags, ResolveFlags};
use rustix::process::{Gid, Uid};

use crate::mount::find_mount;
use crate::CONTROL_FILES;

const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
const SAFE_RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_XDEV)
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);
const ROOT_RESOLVE: ResolveFlags = ResolveFlags::NO_SYMLINKS.union(ResolveFlags::NO_MAGICLINKS);
const OPEN_DIR: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);
const OPEN_DIR_PATH: OFlags = OFlags::PATH.union(OFlags::DIRECTORY).union(OFlags::CLOEXEC);
const OPEN_CONTROL_READ: OFlags = OFlags::RDONLY.union(OFlags::CLOEXEC);
const OPEN_CONTROL_PATH: OFlags = OFlags::PATH.union(OFlags::CLOEXEC);
const OPEN_CONTROL_WRITE: OFlags = OFlags::WRONLY.union(OFlags::CLOEXEC);
const OPEN_CONTROL_REPLACE: OFlags = OPEN_CONTROL_WRITE.union(OFlags::TRUNC);
const OPEN_CONTROL_RW: OFlags = OFlags::RDWR.union(OFlags::CLOEXEC);
const OPEN_CONTROL_CREATE: OFlags = OPEN_CONTROL_RW.union(OFlags::CREATE);

#[derive(Debug)]
struct Root {
    fd: OwnedFd,
    path: PathBuf,
    synthetic_controls: bool,
}

/// A verified cgroup2 mount.
///
/// The root descriptor is opened with symlink resolution disabled. All
/// mutating methods on [`Cgroup`] resolve paths beneath this descriptor.
#[derive(Clone, Debug)]
pub struct Hierarchy {
    root: Arc<Root>,
}

impl Hierarchy {
    /// Discover the process's cgroup2 mount from `/proc/self/mountinfo`.
    pub fn discover() -> io::Result<Self> {
        Self::open(find_mount()?)
    }

    /// Open and verify an explicit cgroup2 mount path.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(invalid("hierarchy path must be absolute"));
        }
        let fd = open_root(path)?;
        if !is_cgroup2(&fd)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a cgroup2 filesystem", path.display()),
            ));
        }
        Ok(Self {
            root: Arc::new(Root {
                fd,
                path: path.to_path_buf(),
                synthetic_controls: false,
            }),
        })
    }

    /// Open a test root without checking its filesystem type.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `path` is a private, non-cgroup2 test
    /// directory and that no untrusted process can replace its entries. This
    /// is intended only for unit tests that need a filesystem-shaped fake
    /// hierarchy; missing control files are synthesized there to model
    /// cgroupfs.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub unsafe fn open_for_test(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(invalid("test hierarchy path must be absolute"));
        }
        let fd = open_root(path)?;
        if is_cgroup2(&fd)? {
            return Err(invalid("test root must not be a cgroup2 filesystem"));
        }
        Ok(Self {
            root: Arc::new(Root {
                fd,
                path: path.to_path_buf(),
                synthetic_controls: true,
            }),
        })
    }

    /// The verified mount path, for display and diagnostics only.
    pub fn mount_path(&self) -> &Path {
        &self.root.path
    }

    /// Return the hierarchy root as a cgroup handle.
    pub fn root(&self) -> Cgroup {
        Cgroup {
            hierarchy: self.clone(),
            path: CgroupPath::root(),
        }
    }

    /// Return a handle for a validated relative cgroup path.
    pub fn at(&self, path: CgroupPath) -> Cgroup {
        Cgroup {
            hierarchy: self.clone(),
            path,
        }
    }

    /// Parse and return a handle for a relative cgroup path.
    pub fn at_path(&self, path: impl AsRef<Path>) -> io::Result<Cgroup> {
        Ok(self.at(CgroupPath::parse(path)?))
    }

    fn open_dir(&self, path: &CgroupPath) -> io::Result<OwnedFd> {
        let mut fd = self.root.fd.try_clone()?;
        for component in path.components() {
            fd = open_child_dir(&fd, component)?;
        }
        Ok(fd)
    }

    fn open_dir_path(&self, path: &CgroupPath) -> io::Result<OwnedFd> {
        let mut fd = self.root.fd.try_clone()?;
        for component in path.components() {
            let name = component_cstring(component)?;
            fd = openat2_checked(
                &fd,
                &name,
                OPEN_DIR_PATH,
                SAFE_RESOLVE,
                "cgroup directory metadata",
            )?;
        }
        Ok(fd)
    }

    fn open_control(
        &self,
        path: &CgroupPath,
        name: &CString,
        flags: OFlags,
    ) -> io::Result<OwnedFd> {
        let dir = self.open_dir(path)?;
        openat2_checked(&dir, name, flags, SAFE_RESOLVE, "control file")
    }
}

/// A validated path relative to a cgroup2 hierarchy root.
///
/// The empty path denotes the hierarchy root. Absolute paths, empty or dot
/// components, `..`, trailing slashes, NUL bytes, and separators inside a
/// component are rejected at construction time.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CgroupPath {
    relative: PathBuf,
}

/// Return this process's cgroup-v2 path as a validated relative path.
pub fn self_relative() -> io::Result<CgroupPath> {
    let text = std::fs::read_to_string("/proc/self/cgroup")?;
    parse_self_cgroup(&text)
}

fn parse_self_cgroup(text: &str) -> io::Result<CgroupPath> {
    for line in text.lines() {
        let Some(path) = line.strip_prefix("0::") else {
            continue;
        };
        let path = path.trim();
        if path.is_empty() {
            return Ok(CgroupPath::root());
        }
        let relative = path
            .strip_prefix('/')
            .ok_or_else(|| invalid("v2 cgroup path is not absolute"))?;
        return CgroupPath::parse(relative);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "process is not in a cgroup v2 hierarchy",
    ))
}

impl CgroupPath {
    /// The hierarchy root path.
    pub fn root() -> Self {
        Self::default()
    }

    /// Parse a relative cgroup path.
    pub fn parse(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let raw = path.as_os_str().as_bytes();
        if raw.is_empty() {
            return Ok(Self::root());
        }
        if raw[0] == b'/' {
            return Err(invalid("cgroup path must be relative"));
        }
        if raw.last() == Some(&b'/') {
            return Err(invalid("cgroup path must not have a trailing slash"));
        }
        if raw
            .split(|byte| *byte == b'/')
            .any(|component| component.is_empty() || component == b"." || component == b"..")
        {
            return Err(invalid("cgroup path contains an illegal component"));
        }
        let mut relative = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Normal(name) => {
                    validate_component(name)?;
                    relative.push(name);
                }
                Component::CurDir
                | Component::ParentDir
                | Component::RootDir
                | Component::Prefix(_) => {
                    return Err(invalid("cgroup path contains an illegal component"));
                }
            }
        }
        Ok(Self { relative })
    }

    /// Append one already-separated cgroup name.
    pub fn child(&self, name: &OsStr) -> io::Result<Self> {
        validate_component(name)?;
        let mut relative = self.relative.clone();
        relative.push(name);
        Ok(Self { relative })
    }

    /// The validated relative path.
    pub fn as_relative(&self) -> &Path {
        &self.relative
    }

    fn components(&self) -> impl Iterator<Item = &OsStr> {
        self.relative
            .components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(name),
                _ => None,
            })
    }

    fn parent_and_name(&self) -> Option<(CgroupPath, &OsStr)> {
        let mut components: Vec<_> = self.components().collect();
        let name = components.pop()?;
        let mut relative = PathBuf::new();
        for component in components {
            relative.push(component);
        }
        Some((Self { relative }, name))
    }
}

impl std::fmt::Display for CgroupPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.relative.display().fmt(f)
    }
}

/// Metadata for one cgroup directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CgroupMetadata {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

/// The kind of a direct child entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    Directory,
    Symlink,
    Other,
}

/// One direct child entry of a cgroup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CgroupEntry {
    pub name: OsString,
    pub kind: EntryKind,
}

/// A handle to one cgroup within a verified [`Hierarchy`].
#[derive(Clone, Debug)]
pub struct Cgroup {
    hierarchy: Hierarchy,
    path: CgroupPath,
}

impl Cgroup {
    /// The validated relative path of this cgroup.
    pub fn path(&self) -> &CgroupPath {
        &self.path
    }

    /// The hierarchy containing this cgroup.
    pub fn hierarchy(&self) -> &Hierarchy {
        &self.hierarchy
    }

    /// Return a child handle without touching the filesystem.
    pub fn child(&self, name: &OsStr) -> io::Result<Self> {
        Ok(Self {
            hierarchy: self.hierarchy.clone(),
            path: self.path.child(name)?,
        })
    }

    /// Return metadata for this cgroup directory.
    pub fn metadata(&self) -> io::Result<CgroupMetadata> {
        let fd = self.hierarchy.open_dir_path(&self.path)?;
        let stat = fs::fstat(&fd).map_err(io::Error::from)?;
        Ok(CgroupMetadata {
            uid: stat.st_uid as u32,
            gid: stat.st_gid as u32,
            mode: stat.st_mode as u32 & 0o7777,
        })
    }

    /// Return direct child entries without following symlinks.
    pub fn entries(&self) -> io::Result<Vec<CgroupEntry>> {
        let fd = self.hierarchy.open_dir(&self.path)?;
        let mut dir = Dir::read_from(&fd).map_err(io::Error::from)?;
        let mut out = Vec::new();
        while let Some(entry) = dir.read() {
            let entry = entry.map_err(io::Error::from)?;
            let name = os_string(entry.file_name().to_bytes());
            if name == OsStr::new(".") || name == OsStr::new("..") {
                continue;
            }
            let kind = match entry.file_type() {
                FileType::Directory => EntryKind::Directory,
                FileType::Symlink => EntryKind::Symlink,
                _ => EntryKind::Other,
            };
            out.push(CgroupEntry { name, kind });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Return all descendant cgroup paths relative to the hierarchy root,
    /// excluding this cgroup.
    pub fn list_groups(&self) -> io::Result<Vec<CgroupPath>> {
        let mut pending = vec![self.path.clone()];
        let mut out = Vec::new();
        while let Some(path) = pending.pop() {
            let cgroup = self.hierarchy.at(path.clone());
            for entry in cgroup.entries()? {
                if entry.kind != EntryKind::Directory {
                    continue;
                }
                let child = path.child(&entry.name)?;
                out.push(child.clone());
                pending.push(child);
            }
        }
        out.sort();
        Ok(out)
    }

    /// Return a validated control-file handle.
    pub fn control(&self, name: &str) -> io::Result<ControlFile<'_>> {
        Ok(ControlFile {
            cgroup: self,
            name: control_name(name)?,
        })
    }

    /// Create/apply this cgroup and optionally attach a pid.
    ///
    /// Missing ancestors are created beneath the verified hierarchy. Existing
    /// ancestors are never re-owned merely because they were traversed.
    pub fn apply(&self, spec: &LeafSpec, attach_pid: Option<u32>) -> io::Result<()> {
        if self.path.as_relative().as_os_str().is_empty() {
            return Err(invalid("cannot apply a leaf to the hierarchy root"));
        }
        validate_spec(spec)?;
        let fd = self.open_dir_for_apply(spec.dperm)?;
        fchown(&fd, spec.uid, spec.gid).map_err(|e| context(e, "set leaf owner"))?;
        if let Some(mode) = spec.dperm {
            fchmod(&fd, mode).map_err(|e| context(e, "set leaf mode"))?;
        }
        // The core control files are part of every v2 cgroup. Only the
        // explicitly synthetic test hierarchy may manufacture missing ones.
        for name in CONTROL_FILES {
            let file =
                match self
                    .hierarchy
                    .open_control(&self.path, &control_name(name)?, OPEN_CONTROL_RW)
                {
                    Ok(file) => file,
                    Err(e)
                        if e.kind() == io::ErrorKind::NotFound
                            && self.hierarchy.root.synthetic_controls =>
                    {
                        let dir = self.hierarchy.open_dir(&self.path)?;
                        create_control(&dir, &control_name(name)?)?
                    }
                    Err(e) => return Err(e),
                };
            let (uid, gid) = match name {
                "cgroup.procs" | "cgroup.threads" => {
                    (spec.task_uid.or(spec.uid), spec.task_gid.or(spec.gid))
                }
                _ => (spec.uid, spec.gid),
            };
            fchown(&file, uid, gid).map_err(|e| context(e, &format!("set {name} owner")))?;
            let mode = match name {
                "cgroup.procs" | "cgroup.threads" => spec.task_fperm.or(spec.fperm),
                _ => spec.fperm,
            };
            if let Some(mode) = mode {
                fchmod(&file, mode).map_err(|e| context(e, "set control mode"))?;
            }
        }
        if !spec.subtree_control.is_empty() {
            self.enable_subtree_control(&spec.subtree_control)?;
        }
        if let Some(pid) = attach_pid {
            self.attach(pid)?;
        }
        Ok(())
    }

    /// Attach a pid by writing the validated `cgroup.procs` control file.
    pub fn attach(&self, pid: u32) -> io::Result<()> {
        self.control("cgroup.procs")?.write_command(pid.to_string())
    }

    /// Enable controllers on this cgroup.
    pub fn enable_subtree_control(&self, controllers: &[String]) -> io::Result<()> {
        validate_controllers(controllers)?;
        let body = controllers
            .iter()
            .map(|controller| format!("+{controller}"))
            .collect::<Vec<_>>()
            .join(" ");
        self.control("cgroup.subtree_control")?.write_command(body)
    }

    /// Remove this empty cgroup. The hierarchy root cannot be removed.
    pub fn delete_leaf(&self) -> io::Result<()> {
        let (parent, name) = self
            .path
            .parent_and_name()
            .ok_or_else(|| invalid("cannot delete the hierarchy root"))?;
        let parent_fd = self.hierarchy.open_dir(&parent)?;
        fs::unlinkat(parent_fd, component_cstring(name)?, AtFlags::REMOVEDIR)
            .map_err(io::Error::from)
    }

    /// Remove this cgroup and all descendants, children first.
    ///
    /// Traversal and removal are descriptor-relative; a symlink or mount
    /// crossing encountered during the walk causes deletion to fail rather
    /// than being followed.
    pub fn delete_tree(&self) -> io::Result<()> {
        if self.path.as_relative().as_os_str().is_empty() {
            return Err(invalid("cannot delete the hierarchy root"));
        }
        let mut pending = vec![self.path.clone()];
        let mut order = Vec::new();
        while let Some(path) = pending.pop() {
            order.push(path.clone());
            let dir = self.hierarchy.open_dir(&path)?;
            let mut entries = Dir::read_from(&dir)?;
            while let Some(entry) = entries.read() {
                let entry = entry?;
                if entry.file_type() != FileType::Directory {
                    continue;
                }
                let name = os_string(entry.file_name().to_bytes());
                if name == OsStr::new(".") || name == OsStr::new("..") {
                    continue;
                }
                pending.push(path.child(&name)?);
            }
        }
        for path in order.into_iter().rev() {
            let (parent, name) = path
                .parent_and_name()
                .ok_or_else(|| invalid("cannot delete the hierarchy root"))?;
            let parent_fd = self.hierarchy.open_dir(&parent)?;
            fs::unlinkat(parent_fd, component_cstring(name)?, AtFlags::REMOVEDIR)
                .map_err(io::Error::from)?;
        }
        Ok(())
    }

    fn open_dir_for_apply(&self, dperm: Option<u32>) -> io::Result<OwnedFd> {
        let components: Vec<_> = self.path.components().collect();
        let last = components.len().saturating_sub(1);
        let mut fd = self.hierarchy.root.fd.try_clone()?;
        for (index, component) in components.into_iter().enumerate() {
            let name = component_cstring(component)?;
            let child =
                match openat2_checked(&fd, &name, OPEN_DIR, SAFE_RESOLVE, "cgroup directory") {
                    Ok(child) => (child, false),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        let mode = dperm.map_or(0o777, |mode| {
                            if index == last {
                                mode
                            } else {
                                ancestor_dperm(mode)
                            }
                        });
                        let created = match fs::mkdirat(&fd, &name, Mode::from(mode & 0o7777)) {
                            Ok(()) => true,
                            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
                            Err(e) => return Err(io::Error::from(e)),
                        };
                        let child = openat2_checked(
                            &fd,
                            &name,
                            OPEN_DIR,
                            SAFE_RESOLVE,
                            "cgroup directory",
                        )?;
                        (child, created)
                    }
                    Err(e) => return Err(e),
                };
            if child.1 && index != last {
                if let Some(mode) = dperm {
                    fchmod(&child.0, ancestor_dperm(mode))?;
                }
            }
            fd = child.0;
        }
        Ok(fd)
    }
}

/// A validated direct child control file of a [`Cgroup`].
pub struct ControlFile<'a> {
    cgroup: &'a Cgroup,
    name: CString,
}

impl ControlFile<'_> {
    /// Return metadata for this control file.
    pub fn metadata(&self) -> io::Result<CgroupMetadata> {
        let fd = self.open_fd(OPEN_CONTROL_PATH)?;
        let stat = fs::fstat(&fd).map_err(io::Error::from)?;
        Ok(CgroupMetadata {
            uid: stat.st_uid as u32,
            gid: stat.st_gid as u32,
            mode: stat.st_mode as u32 & 0o7777,
        })
    }

    /// Read the complete control-file contents, trimmed like the legacy API.
    pub fn read_string(&self) -> io::Result<String> {
        let mut file = self.open(OPEN_CONTROL_READ)?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        Ok(text.trim().to_owned())
    }

    /// Parse a flat key/value control file.
    pub fn read_kv(&self) -> io::Result<Vec<(String, String)>> {
        let text = self.read_string()?;
        Ok(text
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() {
                    return None;
                }
                let (key, value) = line.split_once(char::is_whitespace)?;
                Some((key.to_owned(), value.trim().to_owned()))
            })
            .collect())
    }

    /// Read one unsigned value, returning `None` when the file is absent.
    pub fn read_u64(&self) -> io::Result<Option<u64>> {
        match self.read_string() {
            Ok(text) => text
                .parse::<u64>()
                .map(Some)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Overwrite a control file, normalizing its trailing newline.
    pub fn write(&self, value: impl AsRef<[u8]>) -> io::Result<()> {
        self.write_with_flags(OPEN_CONTROL_REPLACE, value)
    }

    fn write_command(&self, value: impl AsRef<[u8]>) -> io::Result<()> {
        self.write_with_flags(OPEN_CONTROL_WRITE, value)
    }

    fn write_with_flags(&self, flags: OFlags, value: impl AsRef<[u8]>) -> io::Result<()> {
        let mut body = value.as_ref().to_vec();
        while matches!(body.last(), Some(b'\n' | b'\r')) {
            body.pop();
        }
        body.push(b'\n');
        let mut file = self.open(flags)?;
        file.write_all(&body)
    }

    /// Read and parse `cgroup.procs`.
    pub fn procs(&self) -> io::Result<Vec<u32>> {
        let text = self.read_string()?;
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(|line| {
                line.parse::<u32>().map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("bad pid {line:?}: {e}"))
                })
            })
            .collect()
    }

    /// Open the validated control file for writing without exposing its path.
    pub fn open_for_write(&self) -> io::Result<OwnedFd> {
        self.open_fd(OPEN_CONTROL_WRITE)
    }

    fn open(&self, flags: OFlags) -> io::Result<File> {
        Ok(File::from(self.open_fd(flags)?))
    }

    fn open_fd(&self, flags: OFlags) -> io::Result<OwnedFd> {
        let dir = self.cgroup.hierarchy.open_dir(&self.cgroup.path)?;
        openat2_checked(&dir, &self.name, flags, SAFE_RESOLVE, "control file")
    }
}

/// Values to apply to one cgroup leaf.
///
/// The target path is supplied by the [`Cgroup`] receiver, not by this
/// specification, so a spec cannot accidentally escape its hierarchy. Mode
/// values are limited to permission and special bits (`07777`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LeafSpec {
    pub(crate) uid: Option<u32>,
    pub(crate) gid: Option<u32>,
    pub(crate) dperm: Option<u32>,
    pub(crate) fperm: Option<u32>,
    pub(crate) task_fperm: Option<u32>,
    pub(crate) task_uid: Option<u32>,
    pub(crate) task_gid: Option<u32>,
    pub(crate) subtree_control: Vec<String>,
}

impl LeafSpec {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    pub fn gid(mut self, gid: u32) -> Self {
        self.gid = Some(gid);
        self
    }

    pub fn dperm(mut self, mode: u32) -> Self {
        self.dperm = Some(mode);
        self
    }

    pub fn dperm_if_some(mut self, mode: Option<u32>) -> Self {
        self.dperm = mode;
        self
    }

    pub fn fperm(mut self, mode: u32) -> Self {
        self.fperm = Some(mode);
        self
    }

    pub fn fperm_if_some(mut self, mode: Option<u32>) -> Self {
        self.fperm = mode;
        self
    }

    pub fn task_fperm(mut self, mode: u32) -> Self {
        self.task_fperm = Some(mode);
        self
    }

    pub fn task_fperm_if_some(mut self, mode: Option<u32>) -> Self {
        self.task_fperm = mode;
        self
    }

    pub fn task_uid(mut self, uid: u32) -> Self {
        self.task_uid = Some(uid);
        self
    }

    pub fn task_gid(mut self, gid: u32) -> Self {
        self.task_gid = Some(gid);
        self
    }

    pub fn subtree_control(mut self, controllers: &[String]) -> Self {
        self.subtree_control = controllers.to_vec();
        self
    }
}

fn open_root(path: &Path) -> io::Result<OwnedFd> {
    let name = path_to_cstring(path, "hierarchy path")?;
    rustix::fs::openat2(fs::CWD, &name, OPEN_DIR, Mode::empty(), ROOT_RESOLVE)
        .map_err(|e| open_error(e, "open hierarchy root"))
}

fn open_child_dir(parent: &OwnedFd, name: &OsStr) -> io::Result<OwnedFd> {
    openat2_checked(
        parent,
        &component_cstring(name)?,
        OPEN_DIR,
        SAFE_RESOLVE,
        "cgroup directory",
    )
}

fn openat2_checked(
    parent: &OwnedFd,
    name: &CString,
    flags: OFlags,
    resolve: ResolveFlags,
    what: &str,
) -> io::Result<OwnedFd> {
    rustix::fs::openat2(parent, name, flags, Mode::empty(), resolve)
        .map_err(|e| open_error(e, what))
}

fn create_control(parent: &OwnedFd, name: &CString) -> io::Result<OwnedFd> {
    rustix::fs::openat2(
        parent,
        name,
        OPEN_CONTROL_CREATE,
        Mode::from(0o644),
        SAFE_RESOLVE,
    )
    .map_err(|e| open_error(e, "create synthetic control file"))
}

fn open_error(error: rustix::io::Errno, operation: &str) -> io::Error {
    match error {
        rustix::io::Errno::NOSYS | rustix::io::Errno::INVAL => {
            io::Error::new(io::ErrorKind::Unsupported, format!("{operation}: {error}"))
        }
        rustix::io::Errno::LOOP => io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{operation}: symlink refused"),
        ),
        _ => io::Error::from(error),
    }
}

fn is_cgroup2(fd: &OwnedFd) -> io::Result<bool> {
    let stat = fs::fstatfs(fd).map_err(io::Error::from)?;
    Ok(stat.f_type as u64 == CGROUP2_SUPER_MAGIC)
}

fn fchown(fd: &OwnedFd, uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
    fs::fchown(fd, uid.map(Uid::from_raw), gid.map(Gid::from_raw)).map_err(io::Error::from)
}

fn fchmod(fd: &OwnedFd, mode: u32) -> io::Result<()> {
    fs::fchmod(fd, Mode::from(mode)).map_err(io::Error::from)
}

fn validate_spec(spec: &LeafSpec) -> io::Result<()> {
    validate_mode(spec.dperm, "dperm")?;
    validate_mode(spec.fperm, "fperm")?;
    validate_mode(spec.task_fperm, "task_fperm")?;
    validate_controllers(&spec.subtree_control)
}

fn validate_mode(mode: Option<u32>, name: &str) -> io::Result<()> {
    if mode.is_some_and(|value| value & !0o7777 != 0) {
        return Err(invalid(format!(
            "{name} contains file-type or unsupported mode bits"
        )));
    }
    Ok(())
}

fn validate_controllers(controllers: &[String]) -> io::Result<()> {
    for controller in controllers {
        if controller.is_empty()
            || !controller
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
        {
            return Err(invalid(format!("invalid controller name {controller:?}")));
        }
    }
    Ok(())
}

fn validate_component(name: &OsStr) -> io::Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.contains(&0)
    {
        return Err(invalid(format!("invalid cgroup name {name:?}")));
    }
    Ok(())
}

fn control_name(name: &str) -> io::Result<CString> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(invalid(format!("invalid control file name {name:?}")));
    }
    CString::new(name).map_err(|_| invalid("control file name contains NUL"))
}

fn component_cstring(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| invalid("cgroup name contains NUL"))
}

fn path_to_cstring(path: &Path, what: &str) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| invalid(format!("{what} contains NUL")))
}

fn os_string(bytes: &[u8]) -> OsString {
    OsString::from_vec(bytes.to_vec())
}

fn ancestor_dperm(dperm: u32) -> u32 {
    (dperm & !0o022) | 0o011
}

fn context(error: io::Error, operation: &str) -> io::Error {
    io::Error::new(error.kind(), format!("{operation}: {error}"))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn fake_hierarchy() -> (tempfile::TempDir, Hierarchy) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("cg");
        fs::create_dir_all(&root).unwrap();
        let hierarchy = unsafe { Hierarchy::open_for_test(&root) }.unwrap();
        (tmp, hierarchy)
    }

    fn with_controls(path: &Path) {
        fs::create_dir_all(path).unwrap();
        for name in CONTROL_FILES {
            fs::write(path.join(name), "").unwrap();
        }
    }

    #[test]
    fn rejects_unsafe_relative_paths() {
        for path in ["/absolute", "a/../b", "a/./b", "a//b", "a/"] {
            assert_eq!(
                CgroupPath::parse(path).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "path={path:?}"
            );
        }
        assert_eq!(
            CgroupPath::parse("a/b").unwrap().as_relative(),
            Path::new("a/b")
        );
    }

    #[test]
    fn parses_self_cgroup_into_a_validated_path() {
        assert_eq!(
            parse_self_cgroup("0::/users/alice\n")
                .unwrap()
                .as_relative(),
            Path::new("users/alice")
        );
        assert!(parse_self_cgroup("0::/\n")
            .unwrap()
            .as_relative()
            .as_os_str()
            .is_empty());
        assert_eq!(
            parse_self_cgroup("1:cpu:/a\n").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn hierarchy_open_rejects_a_non_cgroup2_filesystem() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(
            Hierarchy::open(tmp.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
        ));
    }

    #[test]
    fn test_root_constructor_does_not_follow_a_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(unsafe { Hierarchy::open_for_test(&link) }.is_err());
    }

    #[test]
    fn applies_and_reads_through_a_handle() {
        let (_tmp, hierarchy) = fake_hierarchy();
        let target = hierarchy.mount_path().join("users/alice");
        with_controls(&target);
        let cgroup = hierarchy.at_path("users/alice").unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let spec = LeafSpec::new()
            .uid(uid)
            .gid(gid)
            .dperm(0o750)
            .fperm(0o640)
            .subtree_control(&["cpu".to_owned()]);
        cgroup.apply(&spec, None).unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o750
        );
        assert_eq!(
            cgroup
                .control("cgroup.subtree_control")
                .unwrap()
                .read_string()
                .unwrap(),
            "+cpu"
        );
        let procs = cgroup.control("cgroup.procs").unwrap();
        procs.write("12\n34").unwrap();
        assert_eq!(procs.procs().unwrap(), vec![12, 34]);
        procs.write("7").unwrap();
        assert_eq!(procs.procs().unwrap(), vec![7]);
        fs::write(target.join("cpu.stat"), "usage_usec 1\nuser_usec 2\n").unwrap();
        assert_eq!(
            cgroup.control("cpu.stat").unwrap().read_kv().unwrap(),
            vec![
                ("usage_usec".to_owned(), "1".to_owned()),
                ("user_usec".to_owned(), "2".to_owned()),
            ]
        );
        assert_eq!(
            cgroup
                .control("memory.current")
                .unwrap()
                .read_u64()
                .unwrap(),
            None
        );
        fs::write(target.join("memory.current"), "4096\n").unwrap();
        assert_eq!(
            cgroup
                .control("memory.current")
                .unwrap()
                .read_u64()
                .unwrap(),
            Some(4096)
        );
        assert!(cgroup.control("cgroup.procs/../escape").is_err());
    }

    #[test]
    fn refuses_to_delete_the_hierarchy_root() {
        let (_tmp, hierarchy) = fake_hierarchy();
        assert_eq!(
            hierarchy.root().delete_leaf().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            hierarchy.root().delete_tree().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn deletes_a_tree_children_first() {
        let (tmp, hierarchy) = fake_hierarchy();
        let root = tmp.path().join("cg");
        fs::create_dir_all(root.join("users/alice/session")).unwrap();
        hierarchy.at_path("users").unwrap().delete_tree().unwrap();
        assert!(!root.join("users").exists());
        assert!(root.exists());
    }

    #[test]
    fn refuses_symlinked_leaf_and_ancestor() {
        let (tmp, hierarchy) = fake_hierarchy();
        let root = tmp.path().join("cg");
        let spec = LeafSpec::new().dperm(0o750);

        let victim = tmp.path().join("victim");
        fs::create_dir_all(&victim).unwrap();
        fs::create_dir_all(root.join("users")).unwrap();
        std::os::unix::fs::symlink(&victim, root.join("users/alice")).unwrap();
        assert!(hierarchy
            .at_path("users/alice/session")
            .unwrap()
            .apply(&spec, None)
            .is_err());
        assert!(!victim.join("session").exists());

        let victim2 = tmp.path().join("victim2");
        fs::create_dir_all(&victim2).unwrap();
        fs::create_dir_all(root.join("safe")).unwrap();
        std::os::unix::fs::symlink(&victim2, root.join("safe/leaf")).unwrap();
        assert!(hierarchy
            .at_path("safe/leaf/child")
            .unwrap()
            .apply(&spec, None)
            .is_err());
        assert!(!victim2.join("child").exists());
    }

    #[test]
    fn refuses_symlinked_control_files() {
        let (tmp, hierarchy) = fake_hierarchy();
        let target = hierarchy.mount_path().join("users/alice");
        with_controls(&target);
        let victim = tmp.path().join("victim");
        fs::write(&victim, "untouched").unwrap();
        fs::remove_file(target.join("cgroup.procs")).unwrap();
        std::os::unix::fs::symlink(&victim, target.join("cgroup.procs")).unwrap();

        let cgroup = hierarchy.at_path("users/alice").unwrap();
        assert!(cgroup
            .control("cgroup.procs")
            .unwrap()
            .write("1234")
            .is_err());
        assert_eq!(fs::read_to_string(victim).unwrap(), "untouched");
    }

    #[test]
    fn rejects_modes_with_file_type_bits_before_creating() {
        let (tmp, hierarchy) = fake_hierarchy();
        let spec = LeafSpec::new().dperm(0o100750);
        let err = hierarchy
            .at_path("bad/leaf")
            .unwrap()
            .apply(&spec, None)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!tmp.path().join("cg/bad").exists());
    }

    #[test]
    fn delete_tree_refuses_to_cross_a_symlink() {
        let (tmp, hierarchy) = fake_hierarchy();
        let root = tmp.path().join("cg");
        let victim = tmp.path().join("victim");
        fs::create_dir_all(&victim).unwrap();
        fs::create_dir_all(root.join("safe")).unwrap();
        std::os::unix::fs::symlink(&victim, root.join("safe/leaf")).unwrap();

        assert!(hierarchy.at_path("safe").unwrap().delete_tree().is_err());
        assert!(victim.exists());
    }

    #[test]
    fn applies_safe_ancestor_modes_when_creating() {
        let (tmp, hierarchy) = fake_hierarchy();
        let root = tmp.path().join("cg");
        let spec = LeafSpec::new().dperm(0o750);
        hierarchy
            .at_path("students/alice")
            .unwrap()
            .apply(&spec, None)
            .unwrap();
        assert_eq!(
            fs::metadata(root.join("students"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o751
        );
        assert_eq!(
            fs::metadata(root.join("students/alice"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
    }
}
