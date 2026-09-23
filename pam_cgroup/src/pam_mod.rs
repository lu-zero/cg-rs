//! `pam_sm_*` entry points. Linked only as a cdylib in practice.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::fs;
use std::io;
use std::ptr;

use cgfs::Hierarchy;

use crate::args::PamArgs;
use crate::classify;
use crate::config::Config;
use crate::place;
use crate::user::User;

// Linux-PAM numeric values from <security/_pam_types.h> (upstream file is
// BSD-3-Clause, Ts'o/Morgan; the integers themselves are not copyrightable
// expression). These are NOT the portable XSSO numbers OpenPAM uses — there
// PAM_SESSION_ERR is 19 and 14 means CRED_UNAVAIL — so keep the Linux gate;
// do not "fix" these against OpenPAM headers.
const PAM_SUCCESS: c_int = 0;
const PAM_SESSION_ERR: c_int = 14;
const PAM_USER: c_int = 2;
const LOG_AUTHPRIV: c_int = 10 << 3;
const LOG_ERR: c_int = 3;
const LOG_INFO: c_int = 6;

// No #[link]: the module is dlopen'ed by the PAM application, whose libpam
// satisfies these symbols at load time. Keeps builds header-free and
// link-free; typos would surface at login, not compile — hence the tiny
// surface (one function).
extern "C" {
    fn pam_get_item(pamh: *const c_void, item: c_int, value: *mut *const c_void) -> c_int;
}

fn log_msg(prio: c_int, msg: &str) {
    if let Ok(c) = CString::new(format!("pam_cgroup_rs: {msg}")) {
        unsafe {
            libc::syslog(LOG_AUTHPRIV | prio, c"%s".as_ptr(), c.as_ptr());
        }
    }
}

fn pam_user(pamh: *const c_void) -> Result<String, c_int> {
    let mut item: *const c_void = ptr::null();
    let rc = unsafe { pam_get_item(pamh, PAM_USER, &mut item) };
    if rc != PAM_SUCCESS || item.is_null() {
        return Err(PAM_SESSION_ERR);
    }
    let name = unsafe { CStr::from_ptr(item.cast::<c_char>()) };
    name.to_str()
        .map(|s| s.to_string())
        .map_err(|_| PAM_SESSION_ERR)
}

fn argv_tokens(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    if argv.is_null() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..argc {
        let p = unsafe { *argv.offset(i as isize) };
        if p.is_null() {
            continue;
        }
        if let Ok(s) = unsafe { CStr::from_ptr(p) }.to_str() {
            out.push(s.to_string());
        }
    }
    out
}

fn open_session(pamh: *const c_void, argc: c_int, argv: *const *const c_char) -> c_int {
    let tokens = argv_tokens(argc, argv);
    let refs: Vec<&str> = tokens.iter().map(String::as_str).collect();
    let (args, unknown) = PamArgs::parse(refs);
    for u in &unknown {
        log_msg(LOG_ERR, &format!("unknown option: {u}"));
    }

    let toml = match Config::load(&args.config) {
        Ok(c) => Some(c),
        Err(e) if e.kind() == io::ErrorKind::NotFound && args.cgrules.is_some() => None,
        Err(e) => {
            log_msg(LOG_ERR, &format!("load {}: {e}", args.config));
            return if cfg_fail_closed(&args.config) {
                PAM_SESSION_ERR
            } else {
                PAM_SUCCESS
            };
        }
    };
    let fail_closed = toml.as_ref().map(|c| c.fail_closed).unwrap_or(false);
    let hierarchy = match toml.as_ref() {
        Some(config) => Hierarchy::open(&config.mount),
        None => Hierarchy::discover(),
    };
    let hierarchy = match hierarchy {
        Ok(hierarchy) => hierarchy,
        Err(e) => {
            log_msg(LOG_ERR, &format!("cgroup hierarchy: {e}"));
            return if fail_closed {
                PAM_SESSION_ERR
            } else {
                PAM_SUCCESS
            };
        }
    };

    let name = match pam_user(pamh) {
        Ok(n) => n,
        Err(e) => {
            log_msg(LOG_ERR, "no PAM_USER");
            return if fail_closed { e } else { PAM_SUCCESS };
        }
    };
    let user = match User::from_name(&name) {
        Ok(u) => u,
        Err(e) => {
            log_msg(LOG_ERR, &format!("user {name}: {e}"));
            return if fail_closed {
                PAM_SESSION_ERR
            } else {
                PAM_SUCCESS
            };
        }
    };
    let pid = std::process::id();

    if let Some(cfg) = &toml {
        match place::apply(cfg, &hierarchy, &user, pid) {
            Ok(steps) => {
                log_msg(
                    LOG_INFO,
                    &format!(
                        "placed uid={} pid={} at {}",
                        user.uid,
                        pid,
                        steps
                            .iter()
                            .find(|s| s.attach)
                            .map(|s| s.cgroup.path().as_relative().display().to_string())
                            .unwrap_or_default()
                    ),
                );
            }
            Err(e) => {
                log_msg(LOG_ERR, &format!("apply: {e}"));
                if fail_closed {
                    return PAM_SESSION_ERR;
                }
            }
        }
    }

    if let Some(cgrules) = &args.cgrules {
        let dir = args.rules_dir().map(std::path::Path::new);
        match classify::classify(
            &hierarchy,
            std::path::Path::new(cgrules),
            dir,
            args.cgconfig.as_deref().map(std::path::Path::new),
            &user,
            pid,
        ) {
            Ok(Some(path)) => {
                log_msg(
                    LOG_INFO,
                    &format!("cgrules uid={} pid={} at {}", user.uid, pid, path.display()),
                );
            }
            Ok(None) => {}
            Err(e) => {
                log_msg(LOG_ERR, &format!("cgrules: {e}"));
                if fail_closed {
                    return PAM_SESSION_ERR;
                }
            }
        }
    }

    PAM_SUCCESS
}

fn cfg_fail_closed(path: &str) -> bool {
    fs::read_to_string(path)
        .ok()
        .and_then(|t| Config::parse(&t).ok())
        .map(|c| c.fail_closed)
        .unwrap_or(false)
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *mut c_void,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let ret = std::panic::catch_unwind(|| open_session(pamh, argc, argv));
    match ret {
        Ok(v) => v,
        Err(_) => {
            log_msg(LOG_ERR, "panic in pam_sm_open_session");
            PAM_SESSION_ERR
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_close_session(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

// Unused PAM groups: return SUCCESS so a mis-stacked line is a no-op.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_chauthtok(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}
