//! Linker notes for the PAM module build.
//!
//! Linux ELF shared objects keep undefined symbols by default, so
//! `pam_get_item` resolves from the host's libpam at dlopen time. Darwin's
//! ld64 rejects them unless told otherwise.

fn main() {
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-undefined,dynamic_lookup");
    }
}
