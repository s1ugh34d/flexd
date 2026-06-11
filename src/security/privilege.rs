#[cfg(unix)]
use nix::unistd::{Uid, setuid, setgid, User};

/// Drop privileges after binding privileged ports (Invariant 9)
#[cfg(unix)]
pub fn drop_privileges(user: &str) -> anyhow::Result<()> {
    if !Uid::effective().is_root() {
        return Ok(()); // Already non-root
    }

    let user = User::from_name(user)?
        .ok_or_else(|| anyhow::anyhow!("User '{}' not found", user))?;

    setgid(user.gid)?;
    setuid(user.uid)?;

    tracing::info!("Dropped privileges to uid={} gid={}", user.uid, user.gid);
    Ok(())
}

#[cfg(not(unix))]
pub fn drop_privileges(_user: &str) -> anyhow::Result<()> {
    Ok(()) // No privilege dropping on non-Unix
}
