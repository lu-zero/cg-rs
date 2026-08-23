//! NSS lookups for config owner fields: name↔id via passwd/group.
//!
//! Mirrors the subset of libcgroup behaviour cgconfigparser has: bare
//! names go through `getpwnam`/`getgrnam`, numeric strings pass through.

use std::ffi::{CStr, CString};
use std::io;

pub fn uid_from_name(name: &str) -> io::Result<u32> {
    if let Ok(n) = name.parse::<u32>() {
        return Ok(n);
    }
    let c = cstr(name)?;
    unsafe {
        let pw = libc::getpwnam(c.as_ptr());
        if pw.is_null() {
            return Err(not_found("user", name));
        }
        Ok((*pw).pw_uid as u32)
    }
}

pub fn gid_from_name(name: &str) -> io::Result<u32> {
    if let Ok(n) = name.parse::<u32>() {
        return Ok(n);
    }
    let c = cstr(name)?;
    unsafe {
        let gr = libc::getgrnam(c.as_ptr());
        if gr.is_null() {
            return Err(not_found("group", name));
        }
        Ok((*gr).gr_gid as u32)
    }
}

/// uid → name, falling back to the numeric value (libcgroup's `%u` rule).
pub fn name_from_uid(uid: u32) -> String {
    unsafe {
        let pw = libc::getpwuid(uid as libc::uid_t);
        if !pw.is_null() {
            if let Ok(s) = CStr::from_ptr((*pw).pw_name).to_str() {
                return s.to_owned();
            }
        }
    }
    uid.to_string()
}

pub fn name_from_gid(gid: u32) -> String {
    unsafe {
        let gr = libc::getgrgid(gid as libc::gid_t);
        if !gr.is_null() {
            if let Ok(s) = CStr::from_ptr((*gr).gr_name).to_str() {
                return s.to_owned();
            }
        }
    }
    gid.to_string()
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in name"))
}

fn not_found(kind: &str, name: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("no such {kind} {name}"))
}

/// Dispatch on the cgconfig.conf field kind ("user" or "group").
pub fn resolve(kind: &str, name: &str) -> io::Result<u32> {
    match kind {
        "user" => uid_from_name(name),
        "group" => gid_from_name(name),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown owner kind {kind}"),
        )),
    }
}
