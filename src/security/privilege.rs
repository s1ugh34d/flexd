//! Post-bind privilege dropping (Invariant 9).
//!
//! Binding low ports (80, 443) needs root, but serving requests as root is a
//! liability. After the listeners are bound,
//! [`drop_privileges`](crate::security::privilege::drop_privileges) permanently
//! drops the process to an unprivileged account, in the correct order
//! (supplementary groups, then gid, then uid) and verifies the drop is
//! irreversible. On non-Unix targets it is a no-op.

#[cfg(unix)]
use nix::unistd::{setgid, setgroups, setuid, Uid, User};

/// Drop privileges after binding privileged ports (Invariant 9).
///
/// Order matters: supplementary groups, then gid, then uid — once the uid is
/// dropped the process can no longer modify its group membership. Without the
/// `setgroups` call the process keeps root's supplementary groups (a classic
/// privilege-separation hole). The drop is verified irreversible afterwards.
///
/// If the process is not running as root this is a no-op (returns `Ok`).
///
/// # Errors
///
/// Returns an error if `user` does not exist, if any of the `setgroups`/
/// `setgid`/`setuid` calls fail, or if the post-drop check finds the process
/// can still regain root.
#[cfg(unix)]
#[cfg_attr(docsrs, doc(cfg(unix)))]
pub fn drop_privileges(user: &str) -> anyhow::Result<()> {
    if !Uid::effective().is_root() {
        return Ok(()); // Already non-root
    }

    let user = User::from_name(user)?
        .ok_or_else(|| anyhow::anyhow!("User '{}' not found", user))?;

    setgroups(&[user.gid])?;
    setgid(user.gid)?;
    setuid(user.uid)?;

    if user.uid.as_raw() != 0 && setuid(Uid::from_raw(0)).is_ok() {
        anyhow::bail!("privilege drop failed: process can still regain root");
    }

    tracing::info!("Dropped privileges to uid={} gid={}", user.uid, user.gid);
    Ok(())
}

#[cfg(not(unix))]
pub fn drop_privileges(_user: &str) -> anyhow::Result<()> {
    Ok(()) // No privilege dropping on non-Unix
}
