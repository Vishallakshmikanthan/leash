# Leash Implementation Document

**Goal:** Turn the Leash prototype into a complete product. Each module below is a separate work item. Gap IDs (G-xx) refer to `leash-gap-report.md`.

| Item | Value |
|------|-------|
| Version | 1.0, Oct 5, 2026 |
| Base | `leash-master` (Python daemon, shim, gates, session, Android app) |
| Effort unit | S under 2 h, M 2 to 6 h, L 6 to 16 h, XL over 16 h. These are estimates for one developer. |

---

## 0. How to read this document

- **Hackathon cut** marks the smallest part of a module that you can finish before the event. Do the cut first.
- **Full** is the complete work.
- Every module has acceptance tests. A module is done when its tests pass in CI.
- Check outside facts (agent hook formats, Android library versions, Office Kit API, model runtimes) in their current documents before you code. They change often.

### Module map

| ID | Module | Closes | Depends on |
|----|--------|--------|------------|
| M0 | Foundation and packaging | G-15, G-17 | none |
| M1 | Trust boundary and control plane | G-01, 02, 03, 06, 16 | M0 |
| M2 | Device pairing and secure transport | G-02, 07, 09 | M1 |
| M3 | Interception layer and agent adapters | G-04, 11, 17 | M1 |
| M4 | Policy and risk engine v2 | G-05 | M0 |
| M5 | Provenance and intent | G-11, 10 | M3, M4 |
| M6 | Gates (Package, Secret, Hidden text, Workflow) | G-12, 14 | M3, M4 |
| M7 | Session, worktree and Rewind | G-16 | M1 |
| M8 | Audit log and receipts | G-08 | M1, M2 |
| M9 | Android app | G-09 | M2 |
| M10 | On-device model | G-10 | M9 |
| M11 | Office Kit integration | G-13 | M2 |
| M12 | Alerts, runaway guard and multi-agent queue | none (finish) | M3, M9 |
| M13 | Developer experience and policy file | none (finish) | M3, M4 |
| M14 | Testing, red team and metrics | G-18 | all |
| M15 | Release and demo readiness | G-19, 20 | all |

### Build order

```
M0 → M1 → M2 → M9 (build + pairing) → M3 → M4 → M8 → M7 → M6 → M5 → M12 → M10 → M11 → M13 → M14 → M15
```

The first six items form the **security core**. Nothing else matters if the approval channel is open.

---

## M0. Foundation and packaging

**Purpose:** Make the project install, run and test the same way on every machine.

**Current state:** `pyproject.toml` lists `pydantic` (unused) and omits `aiohttp`. There is no CI. State lives in `.leash/` inside the repo.

**Hackathon cut (S):**
- Declare `aiohttp` as a dependency. Remove `pydantic`.
- Add `[project.optional-dependencies] dev = ["pytest", "pytest-asyncio"]`.
- Add a `Makefile` with `make test` and `make run`.

**Full (M):**
- Add `.github/workflows/ci.yml`: Python 3.10 to 3.12 on Linux and macOS, `pytest`, `ruff`, and the evasion gate (M14).
- Add a state directory helper: `leash_home()` returns `$XDG_STATE_HOME/leash` (Linux), `~/Library/Application Support/Leash` (macOS) or `%APPDATA%\Leash` (Windows). Create it with mode `0700`.
- Add structured logging with one logger per module.
- Add `docs/README.md` with install and quick start. `pyproject.toml` already points at a `README.md`.

**Files:** `pyproject.toml`, `Makefile`, `.github/workflows/ci.yml`, `daemon/paths.py` (new).

**Acceptance:**
- A clean virtual environment runs `pip install -e .[dev]` then `pytest` with no manual step.
- `leash --help` works.

---

## M1. Trust boundary and control plane

**Purpose:** Make sure the agent can submit actions and nothing else. Only a paired device can decide.

**Current state (G-01, 02, 03, 06):** One HTTP and WebSocket server on `0.0.0.0:8765` serves both the agent and the phone. `POST /decision` needs no signature. `/pairing` returns the secret. The agent gets the secret in its environment and can read `.leash/pairing.json`. The client chooses `cwd` and `session`.

### M1.1 Two planes (L)

| Plane | Who uses it | Transport | Can do | Cannot do |
|-------|-------------|-----------|--------|-----------|
| **Agent plane** | Shim, hooks, agent | Unix domain socket (Windows: named pipe or `127.0.0.1` with token) | Submit action, poll status, post provenance event | Decide, pair, read audit, end a session |
| **Approver plane** | Paired phone | TLS WebSocket (M2) | Receive actions, send signed decisions, pause, resume, rewind | Submit actions as an agent |

**Steps:**
1. Create `daemon/agent_api.py` with routes `POST /v1/action`, `GET /v1/action/{id}`, `POST /v1/provenance`. Bind it to the Unix socket `leash_home()/agent.sock` with mode `0600`.
2. Keep `daemon/server.py` for the approver plane only. Delete these routes: `/decision`, `/pairing`, `/api/pair/pin` (the secret field), `/api/pair/pin/verify` (old form), `/api/test/sample-action`, `/pending`, `/audit`, `/sessions/*` (HTTP form).
3. Move the phone-facing session commands (pause, resume, rewind, scope, runaway decision) into signed WebSocket messages only.
4. If you need test routes, load them only when `LEASH_TEST_ROUTES=1` and the build is a dev build.

### M1.2 Per-session capability token (M)

1. At session start, the daemon creates a random 256-bit token and stores only its hash.
2. `leash run` gives the agent `LEASH_SESSION_TOKEN` and the socket path. It gives **no secret** and no pairing data.
3. Every agent call sends `Authorization: Bearer <token>`. The daemon looks up the session by token. The request body cannot name another session.
4. The token is valid for one session and dies when the session ends.

```python
# daemon/agent_api.py (sketch)
async def post_action(request):
    session = sessions.by_token(request.headers.get("Authorization", "").removeprefix("Bearer "))
    if session is None or session.state != "active":
        return web.json_response({"error": "unauthorized"}, status=401)
    body = await request.json()
    action = ActionRequest.from_agent(body, session=session)   # session comes from the token, not the body
    action.cwd = confine_cwd(body.get("cwd"), session.worktree_path)  # see M1.3
    decision = await daemon.submit_action(action)
    return web.json_response(decision.public_dict())
```

### M1.3 Safe execution (M)

1. `confine_cwd(path, root)`: resolve with `os.path.realpath`. Reject the request if the result is not inside `root`.
2. Run commands with a clean environment: pass only `PATH`, `HOME` (set to a session home), `LANG`, `TERM`, and variables named in the session scope. Never pass `LEASH_*` secrets or cloud tokens.
3. Run the command as the agent user, not with daemon rights. See M3.3 for the container option.
4. Set limits: wall time, output size (for example 1 MB), process group kill on timeout.

### M1.4 Privilege separation (L, Full)

- Run the daemon under a separate OS user (`leashd`) or keep all keys in the OS keyring under a user that the agent cannot read. If the agent and the daemon share one OS user, a file-based secret is readable by the agent. **Say this in the pitch.**
- Hackathon cut: keep one user, but keep keys **outside the worktree and the repo** (`leash_home()` with mode `0700`) and never pass them in the environment. Then use M3.3 (container) for the demo agent so it cannot read `leash_home()`.

### M1.5 Persistence (M, Full)

- Store pending actions in SQLite (`leash_home()/state.db`). On restart, mark all pending actions as `denied: daemon restarted` and tell the phone.
- Remove the global "default session". Create sessions only through `leash run`.

**Files:** `daemon/agent_api.py` (new), `daemon/server.py` (reduce), `daemon/sessions_auth.py` (new), `session/manager.py`, `daemon/cli.py`.

**Acceptance tests (add to CI):**
- An unauthenticated `POST /decision` returns `404`.
- `GET /pairing` returns `404`.
- A request with a wrong or missing token returns `401`.
- A request with a valid token and `cwd=/etc` is rejected.
- The agent environment contains no key. A search of the agent environment for the daemon key finds nothing.
- Re-run the live attack test from the gap report. All four attacks fail.

**Hackathon cut:** M1.1 steps 1 and 2, M1.2, M1.3 items 1 and 2, and the key location in M1.4. **Effort:** about 2 days.

---

## M2. Device pairing and secure transport

**Purpose:** Prove that a decision came from your phone, for this exact action, and keep the link private.

**Current state (G-02, 07, 09):** One shared HMAC secret for everyone. Plain HTTP and WebSocket. The secret travels in clear text. No device list.

### M2.1 Pairing flow (L)

```
Laptop: leash pair
  1. Create (or load) a self-signed TLS certificate. Compute its SHA-256 fingerprint.
  2. Create a one-time pairing token: 128 random bits, valid 120 s, single use.
  3. Show a QR code: leash://pair?host=<ip>&port=<port>&fp=<cert-sha256>&token=<token>

Phone: scan the QR code
  4. Open a TLS connection. Accept ONLY the certificate with fingerprint <fp>.
  5. Create a signing key pair in the Android Keystore (M9.3). Keep the private key on the phone.
  6. Send {token, device_name, public_key} to POST /pair.

Laptop:
  7. Check the token (valid, unused, not expired). Store {device_id, public_key, created_at}.
  8. Delete the token. Reply {device_id}.
```

- The laptop shows the device name and asks you to confirm in the terminal (`Pair "Pixel 8"? [y/N]`).
- Limit the number of wrong tries (for example 5), then stop accepting pairing for 5 minutes.
- `leash devices list` and `leash devices revoke <id>` manage paired phones.

### M2.2 Transport (M)

- Serve the approver plane over TLS (`ssl.SSLContext`, TLS 1.2 or newer, certificate from `cryptography`). Bind to the LAN interface only while pairing mode or a session is on. Otherwise bind to `127.0.0.1`.
- Android: remove `usesCleartextTraffic`. Use OkHttp with a custom `X509TrustManager` that compares the certificate fingerprint. Set `allowBackup="false"`.

### M2.3 Signed decisions (M)

- The daemon sends each action with a fresh server nonce and an `action_digest = SHA-256(canonical(command, cwd, kind, target_path, session, nonce))`.
- The phone signs `{action_id, action_digest, verdict, decided_by, ts, nonce_server}` with its private key (ECDSA P-256, SHA-256).
- The daemon verifies with the stored public key, checks freshness (60 s), checks the nonce was issued for this action and is unused, then records the device id.
- Python and Kotlin must produce **identical canonical bytes**. Use one rule: JSON with sorted keys, no spaces, `ensure_ascii=False`, UTF-8, and escape rules from RFC 8785 (JCS). Add **golden test vectors** (a JSON file of inputs and expected bytes) that both Python and Kotlin tests read. Include non-ASCII text, quotes and control characters. This closes the device-name mismatch from G-09.

```python
# contracts/crypto.py (sketch)
def canonical_json(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def verify_device_signature(pubkey_der: bytes, payload: bytes, sig: bytes) -> bool:
    key = serialization.load_der_public_key(pubkey_der)
    try:
        key.verify(sig, payload, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
```

(`cryptography` is already available in the environment. Add it to `pyproject.toml`.)

**Files:** `daemon/pairing.py` (new), `daemon/tls.py` (new), `contracts/crypto.py`, `contracts/golden/*.json` (new), `LeashCrypto.kt`, `LeashWebSocketClient.kt`, `PairingScreen.kt`, `AndroidManifest.xml`.

**Acceptance tests:**
- A second use of a pairing token fails.
- An expired token fails.
- A phone that pins a wrong fingerprint refuses to connect.
- A decision signed for action A cannot approve action B (digest check).
- A replayed decision is rejected.
- A revoked device is rejected.
- Golden vectors pass in both Python and Kotlin.
- A packet capture of one session shows no readable command text.

**Hackathon cut:** M2.1 with the fingerprint in the QR code, M2.3 with the digest and the per-device key, and the golden vectors. TLS pinning if time allows. **Effort:** about 2 days.

---

## M3. Interception layer and agent adapters

**Purpose:** Make sure a real agent's commands, file reads, file edits and tool calls pass through Leash.

**Current state (G-04, 11, 17):** `ShellShim` works only if a program calls it. `ToolHooks` are Python classes. No agent adapter exists.

### M3.1 Protection levels (S, do first)

Leash must tell the user how strong the protection is, in the CLI and on the phone:

| Level | How | What it stops | What it misses |
|-------|-----|---------------|----------------|
| **L1 Cooperative** | Agent hook plus PATH shims | An agent that follows the hook and uses the shell | A program that calls `/bin/bash` by full path, or a language runtime that spawns a process directly |
| **L2 Contained** | L1 plus a container or `bubblewrap` jail (M3.3) | File access outside the worktree, secrets not mounted, network rules | Kernel escapes, mounted secrets |
| **L3 Isolated** | Separate VM | Almost everything | Convenience |

`leash run` prints the level. The phone shows it on every card.

### M3.2 Agent hook adapter (L)

For each supported agent, write one adapter in `shim/adapters/<agent>.py`. The adapter does three things:
1. Reads the agent's hook input.
2. Calls the agent plane (M1).
3. Returns the verdict in the format the agent expects.

**Example for an agent with pre-tool hooks** (for example Claude Code):
- Configure the agent's `PreToolUse` hook to run `leash hook`.
- The hook reads JSON from standard input (tool name and tool input).
- Map the tool to an `ActionKind`: shell command, file read, file write or edit, web fetch, MCP call.
- Ask the daemon. On allow, exit `0`. On deny, print the reason to standard error and exit with the code that the agent treats as "block". **Verify the exact rules in the agent's current hook documentation before you code.**
- Call the provenance route for every read of an untrusted source (M5).

Write a **generic adapter** too: `leash exec -- <cmd>` already exists. Add `leash hook --format json` for agents that can run a command before each tool use.

`leash init` (M13) installs the hook into the agent's settings file, with a backup of the old file.

### M3.3 Shell shims and containment (L)

1. **PATH shims.** Create `leash_home()/shims/` with small launchers for `bash`, `sh`, `zsh`, `python`, `python3`, `node`, `npm`, `npx`, `pip`, `pipx`, `uv`, `curl`, `wget`, `git`, `ssh`, `scp`, `rsync`, `nc`, `tar`. Each launcher calls `leash exec -- <name> "$@"`, then (after approval) runs the real binary by its absolute path. `leash run` puts the shim directory first in `PATH` and sets `SHELL` to the `bash` shim.
2. **Limit:** An agent can still call `/bin/bash` directly. That is why L2 exists.
3. **Container mode (L2).** `leash run --contain` starts the agent in a container (Docker or Podman) or `bubblewrap` with:
   - only the session worktree mounted read-write,
   - no mount of `$HOME`, `~/.ssh`, `~/.aws`, browser profiles or `leash_home()`,
   - network off, or only through the Leash proxy (M6.5),
   - a non-root user,
   - the agent plane socket mounted read-only for connect.
4. Interpreter child processes: block `exec` of a shell by path inside the container with a seccomp profile only if time allows (Full).

### M3.4 MCP proxy (M, Full)

Add `leash mcp-proxy -- <server command>`. It sits between the agent and an MCP tool server. It sends each tool call to the daemon, applies the same rules, and scans tool descriptions and results for hidden instructions (M6.3). This covers tool-description poisoning.

### M3.5 Platform notes (M)

- Replace `create_subprocess_shell` with `create_subprocess_exec` plus an explicit shell binary per OS (`bash` on Linux and macOS, `powershell` or `cmd` on Windows) chosen in one function.
- Use `pathlib` for all paths. Test on macOS. Mark Windows as unsupported until tested.

**Files:** `shim/adapters/` (new), `shim/shims/` (new), `shim/shell_wrapper.py`, `shim/tool_hooks.py`, `daemon/cli.py` (`run`, `hook`, `init`), `daemon/container.py` (new).

**Acceptance tests:**
- With the shim directory on `PATH`, `curl http://evil.example` inside the agent reaches the daemon.
- A scripted fake agent that follows the hook protocol gets a block on a `deny`.
- In container mode, `cat ~/.ssh/id_rsa` fails because the file does not exist.
- In container mode, a direct `/bin/bash -c 'curl ...'` fails because there is no network.
- The protection level appears in `leash run` output and on the phone card.

**Hackathon cut:** M3.1, one real agent adapter (M3.2) for the agent you will demo, PATH shims (M3.3 item 1) and, if time allows, a Docker run for the demo. **Effort:** 2 to 3 days.

---

## M4. Policy and risk engine v2

**Purpose:** Stop the default-allow behavior. Decide with a real parser.

**Current state (G-05):** Regex rules plus a hand-written tokenizer (`daemon/shell_parser.py`). Unknown commands get severity **low** and run without a phone check. 11 of 27 evasion tests missed.

### M4.1 Three outcomes (M)

Change the evaluator to return one of:
- **ALLOW:** the command matches an explicit allow entry, with argument checks.
- **ASK:** unknown, opaque or medium risk. The phone decides.
- **DENY:** matches a hard rule. No phone prompt (the phone only shows the event).

Remove the rule "low severity runs by default". Severity stays for display. The outcome comes from the table above. Add a config switch `mode: strict | balanced | learning`:
- `strict`: ask for anything not on the allow list.
- `balanced` (default): allow a built-in safe list, ask for the rest.
- `learning`: see M13.

### M4.2 Real shell parsing (L)

- Use a parser library (`bashlex` or `tree-sitter-bash`) to build the command tree. Keep the old tokenizer as a fallback.
- Treat these as separators: `;`, `&&`, `||`, `|`, `&`, **newline**, and subshell `( )`.
- Analyze each simple command separately. The worst result wins.
- **Opaque forms** return ASK: `eval`, `source`, `. file`, `bash -c`, `sh -c`, `$(...)`, backticks, unresolved variable used as a command name (`$a$b`), here-documents that feed a shell, `xargs` with a shell, `find -exec`, `-execdir`.

### M4.3 Argument-aware allow list (M)

Replace prefix matching (`cmd.startswith("pytest ")`) with a table of commands and the arguments they allow:

| Command | Allow | Ask or deny |
|---------|-------|-------------|
| `pytest` | `-q`, `-x`, `-k`, `-v`, test paths inside the worktree | `-p`, `-c`, `--rootdir` outside the worktree, `--import-mode` with unknown plugin |
| `git` | `status`, `diff`, `log`, `show`, `branch`, `add`, `commit` | `-c <key>=<value>`, `--ext-diff`, `--upload-pack`, `--exec-path`, `-C <outside>`, `config core.hooksPath`, `push`, `reset --hard` (ask) |
| `ls` | paths inside the worktree | paths outside the worktree, any sensitive path |
| `npm test` and `npm run <script>` | only if `package.json` scripts are unchanged since the session start (compare a hash) | any change to `scripts` in this session |
| `ruff`, `black`, `flake8` | paths inside the worktree | `--config` outside the worktree |

### M4.4 Interpreters running files (M)

- `bash x.sh`, `sh x.sh`, `python x.py`, `node x.js`, `./x`: find the file. Hash it. Ask the **content scanner** (the preview manager, M6.4) to check it.
- If the agent **wrote or changed the file in this session**, the outcome is at least ASK, and the phone shows the script preview. Keep a session record of "files written by the agent" from the file-write hook.
- Unknown or unreadable file: ASK.

### M4.5 Paths and the network (M)

- Resolve every path argument with `realpath` (symlinks, `..`, `~`). Compare to the scope and the sensitive path list.
- Detect a symlink the agent created in this session that points outside the worktree.
- Network programs (`curl`, `wget`, `nc`, `ssh`, `scp`, `rsync`, `ftp`, `telnet`, interpreters with a network library) are ASK unless the host is on the scope allow list. A pipe from any reader to a network program is DENY (`tar | ssh`, `cat file | nc`).

### M4.6 Evasion corpus as a gate (S)

- Add the 27 cases from the gap report to `corpus/evasion_cases.json`, with the expected outcome.
- `tests/test_evasion.py` fails the build if any case has the wrong outcome.
- Publish the pass rate (the F6 table).

**Files:** `daemon/shell_parser.py`, `daemon/policy_evaluator.py`, `daemon/risk_rules.py`, `daemon/allowlist.py` (new), `corpus/evasion_cases.json`, `tests/test_evasion.py`.

**Acceptance tests:**
- All 27 cases give the expected outcome.
- The normal-development corpus (`corpus/normal_commands.json`) still gives ALLOW for at least 95% of entries in `balanced` mode.
- Any command that the parser cannot parse gives ASK.

**Hackathon cut:** M4.1, the newline fix, M4.3 for `pytest`, `git` and `ls`, M4.4 for `bash`, `python` and `node` files, and M4.6. **Effort:** 2 days.

---

## M5. Provenance and intent

**Purpose:** Raise the risk level when untrusted text came before a risky action. Compare the action with the task.

**Current state (G-11, 10):** The tracker and taint logic work in tests. No real agent feeds them. Intent check has no model.

### M5.1 Real taint sources (M)

Mark the session as tainted when a hook reports a read of:
- a file outside the user's own code (README of a cloned repo, `docs/`, `issues/`, downloaded files),
- a web page or fetched URL,
- the output of an MCP tool,
- an issue, pull request or comment fetched with `gh` or an API client,
- a file that contains hidden text (M6.3).

Record the source path and line. Keep the taint until the user clears it on the phone.

### M5.2 Escalation (S)

A tainted session raises the outcome by one step (ALLOW becomes ASK, ASK stays ASK with a higher severity). The phone card shows "Follows text from README.md line 42". Test this with the planted README in the demo.

### M5.3 Intent check (M, depends on M10)

- The prompt gives the model the task text, the scope and one action. The model returns JSON: `{"matches_task": true|false, "reason": "..."}`.
- Treat the result as a **hint** only. Show "Possible drift" on the card. Never use it to allow.
- Fallback with no model: compare the action path and executable with the scope contract (N3). Report drift when they differ.
- Measure the false-alarm rate on the normal-development corpus (M14). Turn the feature off in the demo if it exceeds 2%.

**Files:** `gates/provenance_tracker.py`, `shim/adapters/*`, `session/scope.py`, `daemon/risk_explainer.py`, Android `OnDeviceRiskExplainer.kt`.

**Acceptance tests:**
- A planted README in the sandbox repo taints the session and raises the next risky action.
- Clearing taint on the phone removes the escalation.
- Intent check never changes a DENY or ASK into an ALLOW.

**Hackathon cut:** M5.1 for README and web fetch, and M5.2. **Effort:** 1 day.

---

## M6. Gates

### M6.1 Package Gate (L)

**Current state (G-12):** Offline only. Small hard-coded name list. No registry calls.

1. Add a registry client in `gates/registry.py`:
   - npm: `https://registry.npmjs.org/<name>` (publish dates, `scripts`, maintainers).
   - PyPI: `https://pypi.org/pypi/<name>/json` (upload dates, project URLs).
   - Cache responses on disk for 24 hours. Timeout 3 s. On any network error, fall back to offline mode and say so on the card.
2. Signals: package does not exist, first publish under 7 days ago, install script present (npm `preinstall`, `install`, `postinstall`), name within edit distance 2 of a top package, new maintainer in the latest version (if data is present), new entry in the lockfile.
3. Ship top-package lists as data files (`gates/data/top_pypi.json`, `top_npm.json`). Refresh them with a script. Do not hard-code them in Python.
4. Rewrite `npm install` to add `--ignore-scripts` unless the user allows scripts. For `pip`, prefer `--only-binary=:all:` when the user allows.
5. Lockfile diff: after an install, show added and changed packages on the receipt.
6. Remove "online mode" from the pitch until steps 1 to 3 pass tests.

### M6.2 Secret Fence (M)

- In L2 mode, secrets are absent by design (not mounted). In L1 mode, use the file-read hook to block sensitive paths.
- Scrub the environment (M1.3). Never pass variables that match `*_TOKEN`, `*_KEY`, `*_SECRET`, `AWS_*`, `GITHUB_TOKEN`, `NPM_TOKEN` unless the scope allows.
- Canary files: place fake credentials in the worktree. Alert when the file is read (Linux `inotify` with `IN_ACCESS`; macOS `fsevents` does not report reads, so scan commands and diffs instead) or when the canary value appears in a command, a diff or an outbound request.
- Install a `pre-commit` and `pre-push` git hook (M13) that runs the secret scan and the hidden-text scan.

### M6.3 Hidden text (S)

Keep `gates/hidden_text.py`. Add: scan tool descriptions and tool results from the MCP proxy (M3.4), and scan every file the agent reads through the hook.

### M6.4 Script preview (M)

- Block private and loopback addresses in URL fetches (resolve the host, reject `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `::1`). Re-check after each redirect. Allow at most 3 redirects.
- Keep the 256 KB cap. Never run the downloaded script.
- Static checks: `curl | sh` chains, `sudo`, `rm -rf`, base64 decode and run, reads of sensitive paths, downloads of more code.

### M6.5 Egress control (M, Full)

Run a local proxy. In L2 mode, the container can reach only the proxy. The proxy allows the hosts in the session scope (package registry, git remote). Log every blocked host. State the limit: this covers only programs that use the proxy, unless the container network is closed.

### M6.6 Workflow watchlist (S)

Keep `gates/workflow_watchlist.py`. Add `Dockerfile`, `.github/workflows/*`, `package.json` scripts, `pyproject.toml` build hooks, `Makefile`, lockfiles and `.npmrc`. Any agent write to these gives ASK with a diff.

**Files:** `gates/registry.py` (new), `gates/package_gate.py`, `gates/secret_fence.py`, `gates/hidden_text.py`, `daemon/preview_manager.py`, `daemon/egress_proxy.py` (new), `gates/data/*`.

**Acceptance tests:**
- A made-up package name (`reqeusts-secure-utils-x`) gives ASK with "not found".
- A package with an install script gives ASK with the script name.
- With the network off, the gate still returns a verdict and says "offline".
- A preview of `http://127.0.0.1/x.sh` is refused.
- A canary read raises an alert on the phone within 2 s.

**Hackathon cut:** M6.1 steps 1, 2 and 4 for npm and PyPI, M6.2 environment scrub, M6.4 address block. **Effort:** 2 days.

---

## M7. Session, worktree and Rewind

**Purpose:** Limit damage and undo it.

**Current state:** `.leash/worktrees/<id>` lives inside the repo. Snapshots use `refs/leash/<session>/<n>`. Tests pass.

### M7.1 Move state out of the repo (M)

- Create worktrees under `leash_home()/worktrees/<repo-hash>/<session>`. The agent then has no `..` path to daemon files.
- Add `.leash/` to `.gitignore` only for legacy installs.

### M7.2 Snapshot quality (M)

- Include **untracked files** in each snapshot. Use a temporary index: `GIT_INDEX_FILE=<tmp> git add -A && git write-tree`, then `git commit-tree`. Store under `refs/leash/<session>/<n>`.
- Respect `.gitignore` but also snapshot ignored files that the scope marks as important (for example `.env.local`) only if the user opts in.
- After Rewind, check that `git status --porcelain` is empty, or report what remains.
- Hold a lock per session so that two Rewind calls cannot run together.

### M7.3 Branch safety (S)

- The agent works on `leash/<session>`. The git guard blocks `checkout` or `switch` to the base branch, `push`, `reset --hard` and `branch -D` unless the phone approves.
- Merge back with `leash merge <session>` (a human step) that shows the diff and the receipt first.

### M7.4 Honest limits (S)

Say on the phone and in the receipt: Rewind restores repository files only. It does not undo network calls, global installs, database changes or files outside the worktree.

**Files:** `session/worktree.py`, `session/snapshot.py`, `session/manager.py`, `shim/git_guard.py`.

**Acceptance tests:**
- The agent cannot reach daemon files from the worktree path.
- A snapshot restores an untracked file that the agent deleted.
- Two parallel Rewind requests run one after the other.

**Hackathon cut:** M7.1 and the untracked-file snapshot. **Effort:** 1 day.

---

## M8. Audit log and receipts

**Purpose:** Give a record that nobody can quietly change, and that names the true decider.

**Current state (G-08):** Plain JSONL. Forged approval logged as "tap".

### M8.1 Hash chain (M)

Each record stores `prev` (hash of the previous record) and `mac = HMAC(audit_key, prev || canonical(record))`. The audit key is a separate secret held by the daemon (not the device key, not given to the agent).

```python
def append(self, record: dict) -> dict:
    record["prev"] = self.head
    record["mac"] = hmac_sha256(self.audit_key, self.head.encode() + canonical_json(record_without_mac(record))).hex()
    self.head = record["mac"]
    self._file.write(json.dumps(record) + "\n"); self._file.flush(); os.fsync(self._file.fileno())
    return record
```

- `leash audit verify` re-computes the chain and reports the first bad record.
- Store the log in `leash_home()` with mode `0600`, outside every worktree.

### M8.2 True attribution (S)

Each decision record holds `device_id`, `action_digest`, the device signature and `decided_by` set by the **daemon** from the verified channel (`phone-biometric`, `phone-tap`, `rule`, `timeout`). The phone cannot claim "biometric" without a key that needs biometrics (M9.3).

### M8.3 Receipts (S)

- Add the chain head and the number of records to the receipt footer.
- Sign the receipt with the audit key. `leash receipt verify <file>` checks it.
- Add the protection level (M3.1) and the list of settings that were off (for example "intent check off").

**Files:** `daemon/audit_logger.py`, `daemon/receipt_builder.py`, `daemon/cli.py`.

**Acceptance tests:**
- Edit one byte in the log. `leash audit verify` fails and names the record.
- Delete a record. The chain check fails.
- A forged `HTTP` decision (route removed in M1) cannot appear in the log.

**Hackathon cut:** M8.1 and M8.2. **Effort:** 1 day.

---

## M9. Android app

**Purpose:** Make the phone side real and safe.

**Current state (G-09):** About 6,900 lines of Kotlin, never built in this review. Screens exist: pairing, action feed, approval card, session info, audit history, settings, demo sheet, receipt dialog. The app uses OkHttp, Compose, biometric and a foreground service.

### M9.1 Build and run (S to M, do first)

1. Install Android Studio or the command-line SDK (platform 35, build-tools). Set `ANDROID_HOME`.
2. Run `./gradlew assembleDebug` in `android/`. Fix every compile error.
3. Install on your phone. Pair with the daemon. Approve one action end to end.
4. Record the result in `docs/device-test.md` (phone model, Android version, result).

### M9.2 Pairing and storage (M)

- Add a QR scanner (CameraX with ML Kit barcode scanning, or a maintained scanner library; check the current library status).
- Parse `leash://pair?...` with `fp` and `token` (M2.1).
- Store the daemon address, the certificate fingerprint and the device id in `EncryptedSharedPreferences` or a `DataStore` protected by a Keystore key. Do not store any shared secret (M2 removes it).
- Add "Forget this laptop".

### M9.3 Biometric-bound signing key (M)

- Create an EC P-256 key in the Android Keystore with `setUserAuthenticationRequired(true)`. Use `StrongBox` when the device has it.
- For ASK and high-risk cards, call `BiometricPrompt` with a `CryptoObject` that wraps the `Signature`. The decision is signed only after a fingerprint or face check.
- For low and medium cards, you may use a key that needs only the device unlock.
- Remove the on-screen "tap fallback" for high and critical severity. Offer "Deny" instead.
- `decided_by` is then provable (M8.2).

### M9.4 Connection and service (M)

- Reconnect with exponential backoff (1, 2, 4, 8, 16 s, then 30 s).
- Show a clear state: *Connected*, *Reconnecting*, *Laptop unreachable (actions are being denied)*.
- Request `POST_NOTIFICATIONS` at run time (Android 13 and newer). Handle the foreground service type rules of Android 14 and newer. Tell the user to exclude the app from battery optimization.
- Notification actions: **Deny** works from the notification. **Approve** for high-risk opens the app for the biometric check.

### M9.5 Card and queue (M)

- Show: command, risk level, one-line reason, source line when tainted, agent name, worktree, protection level (M3.1), preview (M6.4) and script summary.
- Add `FLAG_SECURE` to the approval screen (no screenshots).
- Group similar cards (M12.3).

### M9.6 Tests (M)

- JVM unit tests for canonical JSON with the golden vectors (M2.3).
- Instrumented test for the pairing screen and the approval flow with a fake server.
- Manual test sheet in `docs/device-test.md`.

**Files:** `android/app/build.gradle.kts` (add CameraX, ML Kit, security-crypto), `AndroidManifest.xml`, `LeashCrypto.kt`, `LeashWebSocketClient.kt`, `PairingScreen.kt`, `ApprovalCard.kt`, `MainActivity.kt`, `LeashForegroundService.kt`.

**Acceptance tests:**
- A clean build passes on CI (`assembleDebug` and unit tests).
- Pair, approve, deny, reconnect after Wi-Fi loss, and restart the app. The pairing survives the restart.
- A decision signed without a fingerprint is impossible for a high-risk card.
- A device name with non-ASCII characters pairs correctly.

**Hackathon cut:** M9.1, a working pairing (PIN is acceptable if QR is late) with persistent storage, the golden vector test and the fixed JSON escape. **Effort:** 2 to 3 days.

---

## M10. On-device model

**Purpose:** Give the phone a real, small model for explanations and the intent hint. Rules still decide.

**Current state (G-10):** No runtime. Template explanations only.

### M10.1 Choose a runtime (M)

Compare two options on **your phone** and pick one by measured results:
- Google AI Edge LLM runtime (MediaPipe LLM Inference or its successor) with a small Gemma class model.
- `llama.cpp` through JNI with a small quantized model.

Check current licenses, model sizes and device support first. Record latency (first token and full answer), memory and battery use for 20 sample prompts.

### M10.2 Prompt and output (M)

- Input: action (command, kind), the rule that fired, severity, taint source, task text.
- Output: JSON with `summary` (max 20 words), `why` (max 30 words), `safer_alternative`, `matches_task`. Constrain the output with a grammar or a schema if the runtime supports it. Validate the JSON. If it fails, use the template.
- Timeout 1.5 s. The card shows the template text at once and replaces it when the model answers. The verdict never waits for the model.
- Strip secrets from the prompt (use the redactor first).

### M10.3 Safety (S)

- The model is never allowed to approve, deny or lower severity.
- Treat command text as untrusted. A prompt-injection string in a command must not change the output format. Add 20 injection strings to the test set.

### M10.4 Evaluation (M)

Make `corpus/explainer_eval.json` with 100 commands and a reference summary. Score by a simple rubric (mentions the true risk, no invented facts). Keep the template if the model scores worse.

**Files:** `OnDeviceRiskExplainer.kt`, `android/app/build.gradle.kts`, `corpus/explainer_eval.json`, `daemon/risk_explainer.py` (remove the claim that it runs a model).

**Acceptance tests:**
- With the model removed, cards still show template text.
- On the test phone, the median answer arrives in under 1.5 s.
- No injection string changes the verdict or breaks the JSON.

**Hackathon cut:** Skip the model. Keep templates. Say "rules decide, templates explain". **Effort:** 2 to 3 days for the full module.

---

## M11. Office Kit integration

**Purpose:** Use Office Kit for real transfers (receipt, diff, preview).

**Current state (G-13):** `daemon/office_kit.py` wraps system clipboard commands. The clipboard decision token reuses the leaked shared secret.

1. **Day 0:** Get the real Office Kit documentation from the organizers. Write down what it can do (file transfer, shared clipboard, screen mirror) and how apps call it.
2. Replace the system-clipboard calls with Office Kit calls where they exist. Keep the old code as a fallback and label the fallback in the UI.
3. Use Office Kit for: sending the receipt to the laptop or phone, sending a diff or script preview to the phone, and mirroring the approval screen for the demo.
4. **Remove the clipboard approval channel as an authority.** If you keep it, a clipboard token must be signed by the device key, bound to one action digest, single use, and valid for 30 s. Any local process can write the clipboard, so treat the clipboard as untrusted input.

**Files:** `daemon/office_kit.py`, Android `ReceiptPrinterDialog.kt`.

**Acceptance tests:**
- A receipt moves from laptop to phone with Office Kit and opens.
- A forged clipboard token is rejected.

**Hackathon cut:** Items 1, 2 and 3 for the receipt only. **Effort:** 0.5 to 1 day, depends on the API.

---

## M12. Alerts, runaway guard and multi-agent queue

### M12.1 Done and stuck alerts (S)

- The daemon sends `session_done` when the agent process exits and `session_stuck` when no action arrives for N minutes while the process is alive (default 5).
- The phone shows a normal notification (not an approval card).

### M12.2 Runaway guard (S)

Keep `session/runaway_guard.py`. Add a daemon-side wall-time limit and an output-size limit (M1.3). Use the phone to extend or stop.

### M12.3 Multi-agent queue (M)

- Each card shows the agent name and worktree.
- Group cards with the same rule and similar command text ("3 agents want to run `npm install`"). One decision applies to the group only after the user opens the group and sees every member.
- Limit group approval to ASK-level actions. High-risk actions stay single.

**Acceptance tests:**
- Kill the agent: the phone gets `session_done` within 3 s.
- Two sessions show separate cards with the right worktree labels.

**Hackathon cut:** M12.1 only. **Effort:** 0.5 day.

---

## M13. Developer experience and policy file

### M13.1 `leash init` (M)

- Detect the repo and supported agents.
- Write the hook config (with a backup), create the shim directory, add the git hooks (M6.2) and write a starter `leash.yml`.
- Print the protection level that results.

### M13.2 `leash.yml` (M)

```yaml
mode: balanced            # strict | balanced | learning
scope:
  paths: ["src/", "tests/"]
  commands: ["pytest", "npm", "git"]
  hosts: ["registry.npmjs.org", "pypi.org", "github.com"]
protect:
  - ".github/workflows/**"
  - "Dockerfile"
  - "package.json#scripts"
allow:
  - cmd: "pytest"
    args_deny: ["-p", "-c"]
```

Load it from the repo root. Check its hash and show a change on the phone ("policy changed by agent?"). An agent write to `leash.yml` is always ASK.

### M13.3 Learning mode (M)

For one session, run in `balanced` mode and record every ASK that the user approved. At the end, propose allow rules (`leash policy suggest`). The user reviews each rule. Never add a rule for a DENY. This reduces alarm fatigue.

### M13.4 Docs (S)

README, quick start, the protection-level table, the limits list, and a short threat model.

**Acceptance tests:**
- `leash init` on a clean sample repo makes a working setup.
- A change to `leash.yml` by the agent raises an ASK.

**Hackathon cut:** M13.1 for one agent and a minimal `leash.yml`. **Effort:** 1 day.

---

## M14. Testing, red team and metrics

### M14.1 Test layers (M)

| Layer | What | Where |
|-------|------|-------|
| Unit | Parser, rules, gates, crypto | `tests/` |
| Integration | Daemon with a real WebSocket client that signs with a test device key | `tests/integration/` |
| Security | The four live attacks from the gap report plus new ones | `tests/security/` |
| End to end | Real daemon, fake agent following the hook protocol, fake phone (WebSocket script) | `tests/e2e/` |
| Device | Real phone and real agent, manual sheet | `docs/device-test.md` |

### M14.2 Security tests to add (M)

- Unsigned decision over any route: rejected.
- Secret not in any response, file in the worktree, or environment of the agent.
- Token of session A cannot read or approve session B.
- Replay and wrong-digest tests.
- Path traversal and symlink tests for `cwd` and file hooks.
- Audit chain tamper tests.

### M14.3 Red-team table (F6) (S)

Run the evasion corpus plus 10 new tricks (for example `python -c` with `os.system`, `git` aliases, `npm` lifecycle scripts, `make` targets, `docker run -v /:/host`). Publish: *caught*, *asked*, *missed*, with a one-line reason. Keep the misses in the table.

### M14.4 Fatigue metric (F7) (S)

Run one fixed task three ways: the agent's own prompts only, Leash `strict`, Leash `balanced`. Count prompts per hour and time to finish. Report the numbers you measure. Do not use the numbers until you have measured them.

### M14.5 Fault tests (M)

- Kill the daemon during an approval: the action is denied.
- Drop Wi-Fi during an approval: the action is denied at timeout, and the phone reconnects.
- Phone locked: the notification still arrives.
- 50 actions in 10 s: the queue stays correct.

### M14.6 Fuzzing (S)

Fuzz the shell parser with random strings and with mutations of the corpus. It must never crash and must return ASK for anything it cannot parse.

**Acceptance:** CI runs layers 1 to 4 on every push. All green.

---

## M15. Release and demo readiness

### M15.1 Demo script (S)

Replace the scripted `leash demo` with a **real** run:
1. Start the daemon and pair the phone.
2. Start the real agent through `leash run` in the sandbox repo with the planted README.
3. The agent reads the README (session tainted, phone shows the source line).
4. The agent tries to send the fake `.env` (phone buzzes, you deny).
5. Show Package Gate on a look-alike package.
6. Show Rewind restoring a deleted file.
7. Show the receipt and move it with Office Kit.

Keep the scripted demo only as a labeled "offline backup". Label it "scripted" on screen.

### M15.2 Claims check (S)

Use the table in section 6 of the gap report. Every claim on a slide needs a test, a measurement or a source.

### M15.3 Rehearsal (S)

- Run the real demo 20 times in a row.
- Prepare a backup phone, a backup laptop and a hotspot (do not depend on venue Wi-Fi).
- Charge all devices. Disable sleep.
- Write the 60-second pitch and 10 questions with answers (include "Why not use the agent's own prompts?", "Is this a sandbox?", "What if the agent calls `/bin/bash`?").

### M15.4 Release checklist

- [ ] All CI tests pass
- [ ] Device test sheet complete
- [ ] `leash audit verify` passes after the demo
- [ ] No secret in the repo or the APK
- [ ] Protection level shown in every demo screen
- [ ] Limits slide ready
- [ ] Roadmap slide lists what is not built

---

## Appendix A. Work plan

### Hackathon cut (Oct 5 to Oct 8)

| Day | Work | Gate |
|-----|------|------|
| Oct 5 | M0 cut. M1.1, M1.2, M1.4 (key location). Install Android SDK and build the app (M9.1). | The 4 live attacks fail. The app builds. |
| Oct 6 | M2.1 and M2.3 (pairing, device key, digest, golden vectors). M9.2 persistent pairing. M8.1 and M8.2. | Real phone approves and denies one action end to end. |
| Oct 7 | M3.1, M3.2 (one real adapter), M3.3 PATH shims. M4.1, M4.3, M4.4, M4.6. | A real agent action reaches the phone. The evasion gate passes. |
| Oct 8 | M5.1 and M5.2. M6.1 cut. M7.1. M11 (receipt). Real demo script (M15.1). Rehearse 20 runs. | 20 clean runs in a row. |

Stop adding features when a gate fails. Cut M6.1, M7.1 and M11 first.

### Full completion (after the event)

| Phase | Modules | Estimate |
|-------|---------|----------|
| 1. Security core | M1 full, M2 full, M8 | 1 week |
| 2. Real interception | M3 full (containers, MCP proxy, more agents) | 1 to 2 weeks |
| 3. Policy and gates | M4 full, M5, M6 full | 2 weeks |
| 4. Phone | M9 full, M10, M12 | 2 weeks |
| 5. Product | M7, M11, M13 | 1 week |
| 6. Quality | M14, M15 | 1 week |

These are estimates for one developer. Two developers can run phases 2 and 4 in parallel.

## Appendix B. Interface summary

**Agent plane (Unix socket, bearer token)**

| Route | Body | Result |
|-------|------|--------|
| `POST /v1/action` | kind, command or target_path, tool name and args, cwd | `{id, status}` then verdict |
| `GET /v1/action/{id}` | none | `{status, verdict, reason}` |
| `POST /v1/provenance` | source, line, kind | `{ok}` |

**Approver plane (TLS WebSocket, paired device)**

| Message | Direction | Content |
|---------|-----------|---------|
| `action` | laptop to phone | action, risk, explanation, preview, server nonce, digest |
| `decision` | phone to laptop | action id, digest, verdict, decided_by, ts, signature |
| `session_event` | laptop to phone | done, stuck, runaway, canary, hidden text |
| `session_command` | phone to laptop | pause, resume, rewind, scope change (signed) |

**Canonical signing rule:** JSON, sorted keys, no spaces, `ensure_ascii=False`, UTF-8. Same bytes in Python and Kotlin, proven by golden vectors.

## Appendix C. Known limits to state in every pitch

- Leash is a policy checkpoint. It is not a complete sandbox. Use L2 or L3 for strong isolation.
- If the agent and the daemon share one OS user and no container, the agent can read daemon files.
- Rewind covers repository files only.
- The package checks rely on public registry data and a list of popular names.
- The on-device model gives hints. Rules decide.
