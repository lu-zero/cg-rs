use std::ffi::CStr;
use std::io;

use libc::{getgrgid, getpwnam, getpwuid};

#[derive(Clone, Debug)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub group: String,
}

impl User {
    pub fn from_name(name: &str) -> io::Result<Self> {
        let cname = std::ffi::CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "username contains NUL"))?;
        unsafe {
            let pw = getpwnam(cname.as_ptr());
            if pw.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no such user {name}"),
                ));
            }
            from_passwd(&*pw)
        }
    }

    pub fn from_uid(uid: u32) -> io::Result<Self> {
        unsafe {
            let pw = getpwuid(uid as libc::uid_t);
            if pw.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no such uid {uid}"),
                ));
            }
            from_passwd(&*pw)
        }
    }
}

unsafe fn from_passwd(pw: &libc::passwd) -> io::Result<User> {
    let name = CStr::from_ptr(pw.pw_name)
        .to_str()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "username not utf-8"))?
        .to_string();
    #[allow(clippy::unnecessary_cast)] // uid_t/gid_t width varies
    let gid = pw.pw_gid as u32;
    let group = {
        let gr = getgrgid(pw.pw_gid);
        if gr.is_null() {
            gid.to_string()
        } else {
            CStr::from_ptr((*gr).gr_name)
                .to_str()
                .unwrap_or("")
                .to_string()
        }
    };
    #[allow(clippy::unnecessary_cast)]
    let uid = pw.pw_uid as u32;
    Ok(User {
        name,
        uid,
        gid,
        group,
    })
}

pub fn expand(template: &str, user: &User) -> String {
    // Single-pass replacement to avoid double expansion when user.name
    // itself contains "{uid}" etc. (POSIX names cannot, but be precise).
    let mut out = String::with_capacity(template.len());
    let mut i = 0;
    let bytes = template.as_bytes();
    while i < bytes.len() {
        if template[i..].starts_with("{user}") {
            out.push_str(&user.name);
            i += 6;
        } else if template[i..].starts_with("{uid}") {
            out.push_str(&user.uid.to_string());
            i += 5;
        } else if template[i..].starts_with("{gid}") {
            out.push_str(&user.gid.to_string());
            i += 5;
        } else if template[i..].starts_with("{group}") {
            out.push_str(&user.group);
            i += 7;
        } else {
            let ch = template[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

pub fn resolve_id(spec: &str, user: &User, is_gid: bool) -> io::Result<u32> {
    let spec = expand(spec, user);
    if let Ok(n) = spec.parse::<u32>() {
        return Ok(n);
    }
    if is_gid {
        let c = std::ffi::CString::new(spec.as_str())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "group contains NUL"))?;
        unsafe {
            let gr = libc::getgrnam(c.as_ptr());
            if gr.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no such group {spec}"),
                ));
            }
            return Ok((*gr).gr_gid as u32);
        }
    }
    Ok(User::from_name(&spec)?.uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> User {
        User {
            name: "lu_zero".into(),
            uid: 1000,
            gid: 10,
            group: "wheel".into(),
        }
    }

    #[test]
    fn expands_path_and_owners() {
        let u = sample();
        assert_eq!(expand("users/{user}/session", &u), "users/lu_zero/session");
        assert_eq!(expand("{uid}", &u), "1000");
        assert_eq!(expand("{group}", &u), "wheel");
    }

    #[test]
    fn resolve_numeric_and_placeholder() {
        let u = sample();
        assert_eq!(resolve_id("{uid}", &u, false).unwrap(), 1000);
        assert_eq!(resolve_id("0", &u, false).unwrap(), 0);
        assert_eq!(resolve_id("{gid}", &u, true).unwrap(), 10);
    }
}
