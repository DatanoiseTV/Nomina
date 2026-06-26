//! Privilege dropping. PicoNS binds privileged sockets (port 53, 853, 443) while
//! running as root, then drops to an unprivileged user so the long-running
//! request-handling process has no special privileges.

use crate::config::PrivilegesConfig;

/// Drop to the configured user/group. Must be called *after* all privileged
/// sockets are bound. A no-op when no user is configured or the process is not
/// running as root.
#[cfg(unix)]
pub fn drop_privileges(cfg: &PrivilegesConfig) -> anyhow::Result<()> {
    use nix::unistd::{Gid, Group, Uid, User, setgid, setuid};

    if cfg.user.is_none() && cfg.group.is_none() {
        return Ok(());
    }

    if !Uid::current().is_root() {
        if cfg.user.is_some() || cfg.group.is_some() {
            tracing::warn!(
                "privilege drop requested but not running as root; staying as current user"
            );
        }
        return Ok(());
    }

    // Resolve target uid/gid.
    let mut target_uid: Option<Uid> = None;
    let mut target_gid: Option<Gid> = None;

    if let Some(uname) = &cfg.user {
        let user = User::from_name(uname)?
            .ok_or_else(|| anyhow::anyhow!("privilege drop: no such user '{uname}'"))?;
        target_uid = Some(user.uid);
        target_gid = Some(user.gid);
    }
    if let Some(gname) = &cfg.group {
        let group = Group::from_name(gname)?
            .ok_or_else(|| anyhow::anyhow!("privilege drop: no such group '{gname}'"))?;
        target_gid = Some(group.gid);
    }

    // Order matters: clear supplementary groups, set the group, then the user.
    // Once the uid changes we can no longer adjust groups.
    // SAFETY: clearing supplementary groups via libc while still root.
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        tracing::warn!("failed to clear supplementary groups: {}", std::io::Error::last_os_error());
    }
    if let Some(gid) = target_gid {
        setgid(gid)?;
    }
    if let Some(uid) = target_uid {
        setuid(uid)?;
        // Sanity check: a root process must not be able to regain root.
        if setuid(Uid::from_raw(0)).is_ok() {
            anyhow::bail!("privilege drop failed: still able to setuid(0)");
        }
    }

    tracing::info!(
        uid = target_uid.map(|u| u.as_raw()),
        gid = target_gid.map(|g| g.as_raw()),
        "dropped privileges"
    );
    Ok(())
}

#[cfg(not(unix))]
pub fn drop_privileges(cfg: &PrivilegesConfig) -> anyhow::Result<()> {
    if cfg.user.is_some() || cfg.group.is_some() {
        tracing::warn!("privilege dropping is only supported on Unix; ignoring");
    }
    Ok(())
}
