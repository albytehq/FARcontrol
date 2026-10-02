//! Linux kernel keyring — OS-backed secret storage (ID-04, ADR-0023).
//!
//! Speaks `add_key(2)` / `keyctl(2)` directly through `libc` — no keyutils
//! userspace tools, no D-Bus, no new dependency. The kernel enforces the
//! permission model (owner-UID only), which is the whole point of putting the
//! secret in the OS keyring instead of on the filesystem.
//!
//! Key placement: the calling user's **persistent** keyring when the kernel
//! provides one (survives logout), falling back to the **user** keyring
//! (KEY_SPEC_USER_KEYRING, per-UID). Key type `user`, description derived from
//! the data dir path so multiple daemons never collide:
//! `farcontrol-agent-<sha256(abs data_dir)[0..16]>`.
//!
//! **Fail-closed environment probe** (ADR-0023): partial keyring
//! implementations exist (e.g. gVisor-style sandboxes implement add_key /
//! update / unlink but not read / search). `usable()` performs a full
//! store→load→remove roundtrip on a scratch key; keyring mode is only offered
//! when the environment can actually read the secret back. Otherwise init
//! refuses with a clear error — the owner falls back to `secret_store="file"`.

use std::path::Path;

const KEY_TYPE: &str = "user";

/// Stable per-data-dir key description. Hashed so the description itself leaks
/// nothing about the path and stays a legal key description.
pub fn key_name(data_dir: &Path) -> String {
    let abs = std::fs::canonicalize(data_dir)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| data_dir.to_string_lossy().to_string());
    let h = crate::crypto::sha256_hex(abs.as_bytes());
    format!("farcontrol-agent-{}", &h[..16])
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod imp {
    use super::KEY_TYPE;
    use std::path::Path;
    use std::sync::OnceLock;

    // x86_64 syscall numbers (see syscall(2) table).
    const SYS_ADD_KEY: libc::c_long = 248;
    const SYS_KEYCTL: libc::c_long = 250;
    // keyctl(2) command numbers (include/linux/keyctl.h).
    const KEYCTL_UNLINK: libc::c_int = 7;
    const KEYCTL_SEARCH: libc::c_int = 8;
    const KEYCTL_READ: libc::c_int = 9;
    const KEYCTL_GET_KEYRING_ID: libc::c_int = 0;
    const KEYCTL_GET_PERSISTENT: libc::c_int = 16;
    // Special keyring IDs (keyctl KEY_SPEC_*).
    const KEY_SPEC_USER_KEYRING: libc::c_int = -4;

    fn os_err(op: &str) -> anyhow::Error {
        anyhow::anyhow!("kernel keyring: {op} failed: {}", std::io::Error::last_os_error())
    }

    /// The keyring to place keys in: the user's persistent keyring when the
    /// kernel provides a usable one, else the per-UID user keyring. Both are
    /// valid targets for add_key / search / unlink.
    fn target_ring() -> anyhow::Result<libc::c_int> {
        // SAFETY: raw syscall; plain integer arguments. Returns a keyring
        // serial (> 0) or -1 with errno.
        let rc = unsafe { libc::syscall(SYS_KEYCTL, KEYCTL_GET_PERSISTENT, 0u32, 0u32) };
        if rc > 0 {
            return Ok(rc as libc::c_int);
        }
        // Persistent keyring unavailable (some sandboxes return 0/-1): the
        // user keyring is the honest fallback — per-UID, kernel-permissioned.
        // Validate it resolves: GET_KEYRING_ID(create=1).
        let rc = unsafe { libc::syscall(SYS_KEYCTL, KEYCTL_GET_KEYRING_ID, KEY_SPEC_USER_KEYRING, 1u32) };
        if rc < 0 {
            return Err(os_err("KEYCTL_GET_KEYRING_ID(user)"));
        }
        Ok(KEY_SPEC_USER_KEYRING)
    }

    /// Insert or update the secret (same type+description ⇒ payload update —
    /// exactly the rotate-in-place semantics we want).
    pub fn store(data_dir: &Path, secret: &str) -> anyhow::Result<()> {
        let ring = target_ring()?;
        let desc = super::key_name(data_dir);
        let payload = secret.as_bytes();
        // SAFETY: pointers are valid for the duration of the syscall.
        let rc = unsafe {
            libc::syscall(
                SYS_ADD_KEY,
                KEY_TYPE.as_ptr(),
                desc.as_ptr(),
                payload.as_ptr(),
                payload.len(),
                ring,
            )
        };
        if rc < 0 {
            return Err(os_err("add_key"));
        }
        Ok(())
    }

    /// Find the key in the target keyring. Ok(None) = not present.
    fn find(ring: libc::c_int, desc: &str) -> anyhow::Result<Option<libc::c_int>> {
        // SAFETY: pointers are valid C strings for the syscall duration.
        let rc = unsafe {
            libc::syscall(
                SYS_KEYCTL,
                KEYCTL_SEARCH,
                ring,
                KEY_TYPE.as_ptr(),
                desc.as_ptr(),
                0u32,
            )
        };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOKEY) || err.raw_os_error() == Some(libc::EKEYEXPIRED) {
                return Ok(None);
            }
            return Err(os_err("KEYCTL_SEARCH"));
        }
        Ok(Some(rc as libc::c_int))
    }

    /// Read the secret. Ok(None) = no such key.
    pub fn load(data_dir: &Path) -> anyhow::Result<Option<String>> {
        let ring = target_ring()?;
        let desc = super::key_name(data_dir);
        let Some(serial) = find(ring, &desc)? else { return Ok(None) };
        // First call: 4 KiB buffer (a token is ~44 bytes; generous is fine).
        let mut buf = vec![0u8; 4096];
        // SAFETY: buf pointer + len describe a valid writable region.
        let mut rc = unsafe { libc::syscall(SYS_KEYCTL, KEYCTL_READ, serial, buf.as_mut_ptr(), buf.len()) };
        if rc < 0 {
            return Err(os_err("KEYCTL_READ"));
        }
        if rc as usize > buf.len() {
            // payload larger than expected — resize once and retry.
            buf.resize(rc as usize, 0);
            rc = unsafe { libc::syscall(SYS_KEYCTL, KEYCTL_READ, serial, buf.as_mut_ptr(), buf.len()) };
            if rc < 0 {
                return Err(os_err("KEYCTL_READ(retry)"));
            }
        }
        let n = rc as usize;
        let s = String::from_utf8(buf[..n].to_vec())
            .map_err(|_| anyhow::anyhow!("kernel keyring: stored secret is not valid UTF-8"))?;
        Ok(Some(s).filter(|s| !s.is_empty()))
    }

    /// Remove the key from the target keyring (idempotent).
    pub fn remove(data_dir: &Path) -> anyhow::Result<()> {
        let ring = target_ring()?;
        let desc = super::key_name(data_dir);
        match find(ring, &desc)? {
            None => Ok(()),
            Some(serial) => {
                // SAFETY: two key serials, both integers.
                let rc = unsafe { libc::syscall(SYS_KEYCTL, KEYCTL_UNLINK, ring, serial) };
                if rc < 0 {
                    return Err(os_err("KEYCTL_UNLINK"));
                }
                Ok(())
            }
        }
    }

    /// **Environment probe (ADR-0023, fail-closed):** can this environment
    /// actually STORE and READ BACK a key? Partial keyring implementations
    /// (gVisor-style sandboxes) accept add_key but reject read/search — a
    /// secret stored there would be unrecoverable, so keyring mode must refuse
    /// to enable. Result is cached (one probe per process).
    pub fn usable() -> bool {
        static PROBE: OnceLock<bool> = OnceLock::new();
        *PROBE.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("frtrol-keyring-probe-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            let ok = (|| -> anyhow::Result<bool> {
                let marker = format!("probe-{}", crate::crypto::gen_nonce());
                store(&dir, &marker)?;
                let back = load(&dir)?.ok_or_else(|| anyhow::anyhow!("probe key unreadable"))?;
                let ok = back == marker;
                remove(&dir)?;
                Ok(ok)
            })()
            .unwrap_or(false);
            let _ = std::fs::remove_dir_all(&dir);
            ok
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::PathBuf;

        fn tmp() -> PathBuf {
            // unique per call — parallel tests must not share key descriptions
            let p = std::env::temp_dir().join(format!("frtrol-keyring-{}-{}", std::process::id(), crate::crypto::gen_nonce()));
            std::fs::create_dir_all(&p).unwrap();
            p
        }

        /// These tests are skipped (loudly) when the environment has a partial
        /// kernel keyring (probe fails). On a real Linux kernel they run.
        fn guard() -> bool {
            if !usable() {
                eprintln!("SKIP: kernel keyring not fully usable in this environment (partial sandbox implementation)");
                return false;
            }
            true
        }

        #[test]
        fn roundtrip_store_load_remove() {
            if !guard() {
                return;
            }
            let dir = tmp();
            let secret = "frtrol-keyring-test-token-abc123";
            store(&dir, secret).unwrap();
            assert_eq!(load(&dir).unwrap().as_deref(), Some(secret));
            remove(&dir).unwrap();
            assert_eq!(load(&dir).unwrap(), None, "key must be gone after remove");
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn store_twice_updates_in_place() {
            if !guard() {
                return;
            }
            let dir = tmp();
            store(&dir, "first-value").unwrap();
            store(&dir, "second-value").unwrap();
            assert_eq!(load(&dir).unwrap().as_deref(), Some("second-value"), "add_key on existing desc must UPDATE");
            remove(&dir).unwrap();
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn key_name_is_stable_and_dir_scoped() {
            let a = tmp();
            let b = tmp();
            let ka = super::super::key_name(&a);
            let kb = super::super::key_name(&b);
            assert_ne!(ka, kb, "different data dirs must map to different keys");
            assert_eq!(ka, super::super::key_name(&a), "same dir must be stable");
            assert!(ka.starts_with("farcontrol-agent-"));
            assert_eq!(ka.len(), "farcontrol-agent-".len() + 16);
            let _ = std::fs::remove_dir_all(&a);
            let _ = std::fs::remove_dir_all(&b);
        }

        #[test]
        fn probe_is_deterministic() {
            // usable() must not flip between calls (cached probe)
            let a = usable();
            assert_eq!(usable(), a);
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod imp {
    use std::path::Path;
    pub fn usable() -> bool {
        false
    }
    pub fn store(_data_dir: &Path, _secret: &str) -> anyhow::Result<()> {
        anyhow::bail!("kernel keyring backend is only built for linux/x86_64 (fail closed)")
    }
    pub fn load(_data_dir: &Path) -> anyhow::Result<Option<String>> {
        anyhow::bail!("kernel keyring backend is only built for linux/x86_64 (fail closed)")
    }
    pub fn remove(_data_dir: &Path) -> anyhow::Result<()> {
        anyhow::bail!("kernel keyring backend is only built for linux/x86_64 (fail closed)")
    }
}

pub use imp::{load, remove, store, usable};
