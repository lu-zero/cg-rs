use std::io;

pub use cgcore::User;

use cgcore::{resolve_owner, OwnerKind};

/// Expand the PAM module's `{user}`, `{uid}`, `{gid}`, and `{group}` fields.
///
/// Do a single pass so a value containing a placeholder-looking substring
/// cannot be expanded a second time.
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
    resolve_owner(
        if is_gid {
            OwnerKind::Group
        } else {
            OwnerKind::User
        },
        &spec,
    )
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
