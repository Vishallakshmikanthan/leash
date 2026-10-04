
---

## 5. Rewind

- **Snapshots**: Before every risky action that a Guard approves, the daemon stores a hidden Git ref `refs/leash/<session>/<n>`. The commit message links the snapshot to the session and `action_id`. The matching `action_evaluated` audit event carries `snapshot_ref`.
- **Request**: `POST /sessions/{id}/rewind` with `{"git_ref": ...}` or `{"action_id": ...}`, or WebSocket `rewind` with the same payload. Without a target, the latest snapshot is used.
- **Guard control**: Rewind sends an `action_request` (`category: "rewind"`, `scope_flags: ["rewind"]`, severity `high`) to the Guard. It runs only after an `allow` decision. No Guard channel, a `deny`, or a timeout means no Rewind (fail closed).
- **Backup**: Before restore, the current state is saved to `refs/leash/<session>/backup-<n>`.
- **Audit**: Each Rewind writes an audit event with `event_type: "rewind"` (verdict, decider, snapshot ref, snapshot action, `restored`). `GET /sessions/{id}/activity` lists them under `rewinds`.
- **Scope**: Rewind restores tracked files and non-ignored untracked files in the session worktree. It does **not** undo network requests, global installs, ignored files, changes outside the repository, or running processes.
