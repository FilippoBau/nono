//! Undo subcommand implementations
//!
//! Handles `nono undo list|show|restore|audit|verify|cleanup`.

use crate::cli::{
    UndoArgs, UndoAuditArgs, UndoCleanupArgs, UndoCommands, UndoListArgs, UndoRestoreArgs,
    UndoShowArgs, UndoVerifyArgs,
};
use crate::config::user::load_user_config;
use crate::undo_session::{
    discover_sessions, format_bytes, load_session, remove_session, total_storage_bytes, undo_root,
    SessionInfo,
};
use colored::Colorize;
use nono::undo::{MerkleTree, ObjectStore, SnapshotManager};
use nono::{NonoError, Result};

/// Prefix used for all undo command output
fn prefix() -> colored::ColoredString {
    "[nono]".truecolor(204, 102, 0)
}

/// Dispatch to the appropriate undo subcommand.
pub fn run_undo(args: UndoArgs) -> Result<()> {
    match args.command {
        UndoCommands::List(args) => cmd_list(args),
        UndoCommands::Show(args) => cmd_show(args),
        UndoCommands::Restore(args) => cmd_restore(args),
        UndoCommands::Audit(args) => cmd_audit(args),
        UndoCommands::Verify(args) => cmd_verify(args),
        UndoCommands::Cleanup(args) => cmd_cleanup(args),
    }
}

// ---------------------------------------------------------------------------
// nono undo list
// ---------------------------------------------------------------------------

fn cmd_list(args: UndoListArgs) -> Result<()> {
    let mut sessions = discover_sessions()?;

    if let Some(n) = args.recent {
        sessions.truncate(n);
    }

    if args.json {
        return print_sessions_json(&sessions);
    }

    if sessions.is_empty() {
        eprintln!("{} No undo sessions found.", prefix());
        return Ok(());
    }

    let total = total_storage_bytes()?;
    eprintln!(
        "{} {} session(s), {} total\n",
        prefix(),
        sessions.len(),
        format_bytes(total)
    );

    for s in &sessions {
        let status = session_status_label(s);
        let cmd = s.metadata.command.join(" ");
        let snapshots = s.metadata.snapshot_count;
        let size = format_bytes(s.disk_size);

        eprintln!(
            "  {} {} {} ({} snapshots, {})",
            s.metadata.session_id.white().bold(),
            status,
            cmd.truecolor(150, 150, 150),
            snapshots,
            size.truecolor(150, 150, 150),
        );

        let paths: Vec<String> = s
            .metadata
            .tracked_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        eprintln!("    paths: {}", paths.join(", ").truecolor(100, 100, 100));
    }

    Ok(())
}

fn print_sessions_json(sessions: &[SessionInfo]) -> Result<()> {
    let entries: Vec<serde_json::Value> = sessions
        .iter()
        .map(|s| {
            serde_json::json!({
                "session_id": s.metadata.session_id,
                "started": s.metadata.started,
                "ended": s.metadata.ended,
                "command": s.metadata.command,
                "tracked_paths": s.metadata.tracked_paths,
                "snapshot_count": s.metadata.snapshot_count,
                "exit_code": s.metadata.exit_code,
                "disk_size": s.disk_size,
                "is_alive": s.is_alive,
                "is_stale": s.is_stale,
            })
        })
        .collect();

    let json = serde_json::to_string_pretty(&entries)
        .map_err(|e| NonoError::Snapshot(format!("JSON serialization failed: {e}")))?;
    println!("{json}");
    Ok(())
}

fn session_status_label(s: &SessionInfo) -> colored::ColoredString {
    if s.is_alive {
        "running".green()
    } else if s.is_stale {
        "stale".yellow()
    } else {
        "completed".truecolor(150, 150, 150)
    }
}

// ---------------------------------------------------------------------------
// nono undo show
// ---------------------------------------------------------------------------

fn cmd_show(args: UndoShowArgs) -> Result<()> {
    let session = load_session(&args.session_id)?;

    if args.json {
        return print_show_json(&session);
    }

    let status = session_status_label(&session);
    eprintln!(
        "{} Session: {} {}",
        prefix(),
        session.metadata.session_id.white().bold(),
        status
    );
    eprintln!(
        "  Command:  {}",
        session.metadata.command.join(" ").truecolor(150, 150, 150)
    );
    eprintln!("  Started:  {}", session.metadata.started);
    if let Some(ref ended) = session.metadata.ended {
        eprintln!("  Ended:    {ended}");
    }
    if let Some(code) = session.metadata.exit_code {
        eprintln!("  Exit:     {code}");
    }
    eprintln!("  Size:     {}", format_bytes(session.disk_size));

    let paths: Vec<String> = session
        .metadata
        .tracked_paths
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    eprintln!("  Paths:    {}", paths.join(", "));
    eprintln!();

    // Print snapshot timeline
    for i in 0..session.metadata.snapshot_count {
        let manifest = match SnapshotManager::load_manifest_from(&session.dir, i) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if i == 0 {
            eprintln!(
                "  [{}] Baseline  {} files  {}",
                format!("{i:03}").white().bold(),
                manifest.files.len(),
                manifest.timestamp.truecolor(100, 100, 100)
            );
        } else {
            let changes = SnapshotManager::load_changes_from(&session.dir, i).unwrap_or_default();
            let (created, modified, deleted) = count_change_types(&changes);

            eprintln!(
                "  [{}] Snapshot  +{created} ~{modified} -{deleted}  {}",
                format!("{i:03}").white().bold(),
                manifest.timestamp.truecolor(100, 100, 100)
            );
        }
    }

    Ok(())
}

fn print_show_json(session: &SessionInfo) -> Result<()> {
    let mut snapshots = Vec::new();
    for i in 0..session.metadata.snapshot_count {
        let manifest = match SnapshotManager::load_manifest_from(&session.dir, i) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let changes = SnapshotManager::load_changes_from(&session.dir, i).unwrap_or_default();

        snapshots.push(serde_json::json!({
            "number": manifest.number,
            "timestamp": manifest.timestamp,
            "parent": manifest.parent,
            "file_count": manifest.files.len(),
            "merkle_root": manifest.merkle_root.to_string(),
            "changes": changes.iter().map(|c| serde_json::json!({
                "path": c.path.display().to_string(),
                "type": format!("{}", c.change_type),
                "size_delta": c.size_delta,
            })).collect::<Vec<_>>(),
        }));
    }

    let output = serde_json::json!({
        "session_id": session.metadata.session_id,
        "started": session.metadata.started,
        "ended": session.metadata.ended,
        "command": session.metadata.command,
        "tracked_paths": session.metadata.tracked_paths,
        "exit_code": session.metadata.exit_code,
        "disk_size": session.disk_size,
        "is_alive": session.is_alive,
        "is_stale": session.is_stale,
        "snapshots": snapshots,
    });

    let json = serde_json::to_string_pretty(&output)
        .map_err(|e| NonoError::Snapshot(format!("JSON serialization failed: {e}")))?;
    println!("{json}");
    Ok(())
}

// ---------------------------------------------------------------------------
// nono undo restore
// ---------------------------------------------------------------------------

fn cmd_restore(args: UndoRestoreArgs) -> Result<()> {
    let session = load_session(&args.session_id)?;

    if args.snapshot >= session.metadata.snapshot_count {
        return Err(NonoError::Snapshot(format!(
            "Snapshot {} does not exist (session has {} snapshots)",
            args.snapshot, session.metadata.snapshot_count
        )));
    }

    let manifest = SnapshotManager::load_manifest_from(&session.dir, args.snapshot)?;

    // For restore we need to construct a SnapshotManager with the tracked paths
    // and a minimal exclusion filter (we're restoring, not snapshotting)
    let exclusion_config = nono::undo::ExclusionConfig {
        use_gitignore: false,
        exclude_patterns: Vec::new(),
        exclude_globs: Vec::new(),
        force_include: Vec::new(),
    };

    // Use the first tracked path as the root for the exclusion filter
    let filter_root = session
        .metadata
        .tracked_paths
        .first()
        .cloned()
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let exclusion = nono::undo::ExclusionFilter::new(exclusion_config, &filter_root)?;
    let manager = SnapshotManager::new(
        session.dir.clone(),
        session.metadata.tracked_paths.clone(),
        exclusion,
    )?;

    if args.dry_run {
        let diff = manager.compute_restore_diff(&manifest)?;
        if diff.is_empty() {
            eprintln!("{} No changes needed (already matches snapshot).", prefix());
            return Ok(());
        }

        eprintln!(
            "{} Dry run: restoring to snapshot {} would apply {} change(s):\n",
            prefix(),
            args.snapshot,
            diff.len()
        );
        print_changes(&diff);
        return Ok(());
    }

    let applied = manager.restore_to(&manifest)?;

    if applied.is_empty() {
        eprintln!("{} No changes needed (already matches snapshot).", prefix());
    } else {
        eprintln!(
            "{} Restored {} file(s) to snapshot {}.",
            prefix(),
            applied.len(),
            args.snapshot
        );
        print_changes(&applied);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// nono undo audit
// ---------------------------------------------------------------------------

fn cmd_audit(args: UndoAuditArgs) -> Result<()> {
    let session = load_session(&args.session_id)?;

    if args.json {
        return print_audit_json(&session);
    }

    eprintln!(
        "{} Audit trail for session: {}",
        prefix(),
        session.metadata.session_id.white().bold()
    );
    eprintln!(
        "  Command:  {}",
        session.metadata.command.join(" ").truecolor(150, 150, 150)
    );
    eprintln!("  Started:  {}", session.metadata.started);
    if let Some(ref ended) = session.metadata.ended {
        eprintln!("  Ended:    {ended}");
    }
    if let Some(code) = session.metadata.exit_code {
        eprintln!("  Exit:     {code}");
    }
    eprintln!();

    for i in 0..session.metadata.snapshot_count {
        let manifest = match SnapshotManager::load_manifest_from(&session.dir, i) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if i == 0 {
            eprintln!(
                "  [{}] Baseline at {}  ({} files, root: {})",
                format!("{i:03}").white().bold(),
                manifest.timestamp,
                manifest.files.len(),
                &manifest.merkle_root.to_string()[..16],
            );
        } else {
            let changes = SnapshotManager::load_changes_from(&session.dir, i).unwrap_or_default();
            eprintln!(
                "  [{}] Snapshot at {}  (root: {})",
                format!("{i:03}").white().bold(),
                manifest.timestamp,
                &manifest.merkle_root.to_string()[..16],
            );

            for change in &changes {
                let symbol = change_symbol(&change.change_type);
                eprintln!("        {} {}", symbol, change.path.display());
            }
        }
    }

    Ok(())
}

fn print_audit_json(session: &SessionInfo) -> Result<()> {
    let mut snapshots = Vec::new();
    for i in 0..session.metadata.snapshot_count {
        let manifest = match SnapshotManager::load_manifest_from(&session.dir, i) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let changes = SnapshotManager::load_changes_from(&session.dir, i).unwrap_or_default();

        snapshots.push(serde_json::json!({
            "number": manifest.number,
            "timestamp": manifest.timestamp,
            "file_count": manifest.files.len(),
            "merkle_root": manifest.merkle_root.to_string(),
            "changes": changes.iter().map(|c| serde_json::json!({
                "path": c.path.display().to_string(),
                "type": format!("{}", c.change_type),
                "size_delta": c.size_delta,
                "old_hash": c.old_hash.map(|h| h.to_string()),
                "new_hash": c.new_hash.map(|h| h.to_string()),
            })).collect::<Vec<_>>(),
        }));
    }

    let output = serde_json::json!({
        "session_id": session.metadata.session_id,
        "started": session.metadata.started,
        "ended": session.metadata.ended,
        "command": session.metadata.command,
        "tracked_paths": session.metadata.tracked_paths,
        "exit_code": session.metadata.exit_code,
        "merkle_roots": session.metadata.merkle_roots.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        "snapshots": snapshots,
    });

    let json = serde_json::to_string_pretty(&output)
        .map_err(|e| NonoError::Snapshot(format!("JSON serialization failed: {e}")))?;
    println!("{json}");
    Ok(())
}

// ---------------------------------------------------------------------------
// nono undo verify
// ---------------------------------------------------------------------------

fn cmd_verify(args: UndoVerifyArgs) -> Result<()> {
    let session = load_session(&args.session_id)?;
    let object_store = ObjectStore::new(session.dir.clone())?;

    eprintln!(
        "{} Verifying session: {}",
        prefix(),
        session.metadata.session_id.white().bold()
    );

    let mut all_passed = true;
    let mut objects_checked = 0u64;

    for i in 0..session.metadata.snapshot_count {
        let manifest = match SnapshotManager::load_manifest_from(&session.dir, i) {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "  [{}] {} Failed to load: {e}",
                    format!("{i:03}").white(),
                    "FAIL".red()
                );
                all_passed = false;
                continue;
            }
        };

        // Rebuild Merkle tree from file hashes and compare
        let rebuilt = MerkleTree::from_manifest(&manifest.files)?;
        let merkle_ok = *rebuilt.root() == manifest.merkle_root;

        if !merkle_ok {
            eprintln!(
                "  [{}] {} Merkle root mismatch (stored: {}, rebuilt: {})",
                format!("{i:03}").white(),
                "FAIL".red(),
                &manifest.merkle_root.to_string()[..16],
                &rebuilt.root().to_string()[..16],
            );
            all_passed = false;
            continue;
        }

        // Verify referenced objects in the store
        let mut snapshot_ok = true;
        for state in manifest.files.values() {
            match object_store.verify(&state.hash) {
                Ok(true) => {
                    objects_checked = objects_checked.saturating_add(1);
                }
                Ok(false) => {
                    snapshot_ok = false;
                    all_passed = false;
                }
                Err(_) => {
                    snapshot_ok = false;
                    all_passed = false;
                }
            }
        }

        let status = if snapshot_ok {
            "OK".green()
        } else {
            all_passed = false;
            "FAIL".red()
        };

        eprintln!(
            "  [{}] {} Merkle root matches, {} objects verified",
            format!("{i:03}").white(),
            status,
            manifest.files.len(),
        );
    }

    eprintln!();
    if all_passed {
        eprintln!(
            "{} {} All {} snapshot(s) verified, {} objects checked.",
            prefix(),
            "PASS".green().bold(),
            session.metadata.snapshot_count,
            objects_checked,
        );
    } else {
        eprintln!(
            "{} {} Some snapshots failed verification.",
            prefix(),
            "FAIL".red().bold(),
        );
        return Err(NonoError::Snapshot(
            "Session integrity verification failed".to_string(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// nono undo cleanup
// ---------------------------------------------------------------------------

fn cmd_cleanup(args: UndoCleanupArgs) -> Result<()> {
    if args.all {
        return cleanup_all(args.dry_run);
    }

    let sessions = discover_sessions()?;
    if sessions.is_empty() {
        eprintln!("{} No undo sessions to clean up.", prefix());
        return Ok(());
    }

    let config = load_user_config()?.unwrap_or_default();
    let keep = args.keep.unwrap_or(config.undo.max_sessions);

    let mut to_remove: Vec<&SessionInfo> = Vec::new();

    // Filter by --older-than
    if let Some(days) = args.older_than {
        let cutoff_secs = days.saturating_mul(86400);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for s in &sessions {
            if let Ok(started) = s.metadata.started.parse::<u64>() {
                if now.saturating_sub(started) > cutoff_secs && !s.is_alive {
                    to_remove.push(s);
                }
            }
        }
    } else {
        // Default: remove stale sessions + enforce keep limit
        let stale_grace_secs = config.undo.stale_grace_hours.saturating_mul(3600);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Stale sessions (ended is None, PID dead)
        for s in &sessions {
            if s.is_stale {
                if let Ok(started) = s.metadata.started.parse::<u64>() {
                    if now.saturating_sub(started) > stale_grace_secs {
                        to_remove.push(s);
                    }
                }
            }
        }

        // Excess sessions beyond keep limit (sessions already sorted newest-first)
        let completed: Vec<&SessionInfo> = sessions.iter().filter(|s| !s.is_alive).collect();

        if completed.len() > keep {
            for s in &completed[keep..] {
                if !to_remove
                    .iter()
                    .any(|r| r.metadata.session_id == s.metadata.session_id)
                {
                    to_remove.push(s);
                }
            }
        }
    }

    if to_remove.is_empty() {
        eprintln!("{} Nothing to clean up.", prefix());
        return Ok(());
    }

    let total_size: u64 = to_remove.iter().map(|s| s.disk_size).sum();

    if args.dry_run {
        eprintln!(
            "{} Dry run: would remove {} session(s) ({})\n",
            prefix(),
            to_remove.len(),
            format_bytes(total_size)
        );
        for s in &to_remove {
            eprintln!(
                "  {} {} ({})",
                s.metadata.session_id,
                s.metadata.command.join(" ").truecolor(150, 150, 150),
                format_bytes(s.disk_size).truecolor(150, 150, 150),
            );
        }
        return Ok(());
    }

    let mut removed = 0usize;
    for s in &to_remove {
        if let Err(e) = remove_session(&s.dir) {
            eprintln!(
                "{} Failed to remove {}: {e}",
                prefix(),
                s.metadata.session_id
            );
        } else {
            removed = removed.saturating_add(1);
        }
    }

    eprintln!(
        "{} Removed {} session(s), freed {}.",
        prefix(),
        removed,
        format_bytes(total_size)
    );

    Ok(())
}

fn cleanup_all(dry_run: bool) -> Result<()> {
    let root = undo_root()?;
    if !root.exists() {
        eprintln!("{} No undo directory found.", prefix());
        return Ok(());
    }

    let sessions = discover_sessions()?;
    let alive_count = sessions.iter().filter(|s| s.is_alive).count();

    if alive_count > 0 {
        eprintln!(
            "{} {} session(s) still running, skipping those.",
            prefix(),
            alive_count,
        );
    }

    let removable: Vec<&SessionInfo> = sessions.iter().filter(|s| !s.is_alive).collect();
    let total_size: u64 = removable.iter().map(|s| s.disk_size).sum();

    if removable.is_empty() {
        eprintln!("{} No sessions to remove.", prefix());
        return Ok(());
    }

    if dry_run {
        eprintln!(
            "{} Dry run: would remove {} session(s) ({})",
            prefix(),
            removable.len(),
            format_bytes(total_size)
        );
        return Ok(());
    }

    let mut removed = 0usize;
    for s in &removable {
        if let Err(e) = remove_session(&s.dir) {
            eprintln!(
                "{} Failed to remove {}: {e}",
                prefix(),
                s.metadata.session_id
            );
        } else {
            removed = removed.saturating_add(1);
        }
    }

    eprintln!(
        "{} Removed {} session(s), freed {}.",
        prefix(),
        removed,
        format_bytes(total_size)
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn count_change_types(changes: &[nono::undo::Change]) -> (usize, usize, usize) {
    let mut created = 0usize;
    let mut modified = 0usize;
    let mut deleted = 0usize;
    for c in changes {
        match c.change_type {
            nono::undo::ChangeType::Created => created = created.saturating_add(1),
            nono::undo::ChangeType::Modified => modified = modified.saturating_add(1),
            nono::undo::ChangeType::Deleted => deleted = deleted.saturating_add(1),
            nono::undo::ChangeType::PermissionsChanged => modified = modified.saturating_add(1),
        }
    }
    (created, modified, deleted)
}

fn change_symbol(ct: &nono::undo::ChangeType) -> colored::ColoredString {
    match ct {
        nono::undo::ChangeType::Created => "+".green(),
        nono::undo::ChangeType::Modified => "~".yellow(),
        nono::undo::ChangeType::Deleted => "-".red(),
        nono::undo::ChangeType::PermissionsChanged => "p".truecolor(150, 150, 150),
    }
}

fn print_changes(changes: &[nono::undo::Change]) {
    for change in changes {
        let symbol = change_symbol(&change.change_type);
        eprintln!("  {} {}", symbol, change.path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_change_types_empty() {
        let (c, m, d) = count_change_types(&[]);
        assert_eq!((c, m, d), (0, 0, 0));
    }

    #[test]
    fn count_change_types_mixed() {
        use nono::undo::{Change, ChangeType};
        use std::path::PathBuf;

        let changes = vec![
            Change {
                path: PathBuf::from("a.txt"),
                change_type: ChangeType::Created,
                size_delta: None,
                old_hash: None,
                new_hash: None,
            },
            Change {
                path: PathBuf::from("b.txt"),
                change_type: ChangeType::Modified,
                size_delta: None,
                old_hash: None,
                new_hash: None,
            },
            Change {
                path: PathBuf::from("c.txt"),
                change_type: ChangeType::Deleted,
                size_delta: None,
                old_hash: None,
                new_hash: None,
            },
            Change {
                path: PathBuf::from("d.txt"),
                change_type: ChangeType::PermissionsChanged,
                size_delta: None,
                old_hash: None,
                new_hash: None,
            },
        ];
        let (c, m, d) = count_change_types(&changes);
        assert_eq!(c, 1);
        assert_eq!(m, 2); // Modified + PermissionsChanged
        assert_eq!(d, 1);
    }
}
