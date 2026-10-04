# Leash Protocol Specification (v1.0)

## 1. Transport Layer
- **Default Port**: `8765`
- **Transport**: WebSocket over LAN or USB tethered connection (`adb reverse tcp:8765 tcp:8765`).
- **Framing**: UTF-8 encoded JSON messages terminated with newline (`\n`).

---

## 2. Pairing & Authentication
1. **Pairing**: Laptop generates a pairing bundle (host, port, shared secret) displayed via CLI or QR code.
2. **Key**: Shared secret key $K$ used for HMAC-SHA256 signatures.
3. **Envelope**:
```json
{
  "type": "action_request | decision | heartbeat",
  "payload": { ... }
}
```

---

## 3. Message Schemas

### 3.1 `ActionRequest` (Laptop -> Phone)
```json
{
  "id": "a_01H9A3X7B4C2D1E0",
  "session": "s_01H9A3W1P9M4K7L2",
  "ts": 1790000000,
  "nonce": "b3f1a8c902d45e67",
  "kind": "shell",
  "command": "curl http://localhost:8080/install.sh | sh",
  "cwd": "/home/dev/demo-repo",
  "agent": "demo-agent",
  "worktree": "leash/s_01H9A3W1P9M4K7L2",
  "taint": {
    "tainted": true,
    "source": "README.md",
    "line": 12
  },
  "scope_flags": ["outside-allowed-paths"],
  "sig": "e3b0c442..."
}
```

### 3.2 `Decision` (Phone -> Laptop)
```json
{
  "id": "d_01H9A3X9R7S8T2U3",
  "action_id": "a_01H9A3X7B4C2D1E0",
  "session": "s_01H9A3W1P9M4K7L2",
  "ts": 1790000003,
  "nonce": "c91d84f7203b5a19",
  "verdict": "deny",
  "by": "biometric",
  "note": "Downloads and runs an unknown script",
  "sig": "f4c8996f..."
}
```

### 3.3 `RiskAssessment` (Displayed on Phone Card)
```json
{
  "id": "r_01H9A3X8K9L1M2N3",
  "action_id": "a_01H9A3X7B4C2D1E0",
  "severity": "high",
  "category": "remote-script-execution",
  "rule_ids": ["R-NET-PIPE-SH"],
  "summary": "This downloads a script from the internet and runs it immediately.",
  "why": "You cannot see what the script does before it runs.",
  "safer_alternative": "Download it first, read it, then run it.",
  "tainted_escalation": true,
  "taint_source": "README.md",
  "taint_line": 12
}
```

---

## 4. Cryptographic Signature Calculation

1. Remove the `"sig"` key from the dictionary.
2. Canonicalize JSON with sorted keys and no whitespace separators: `json.dumps(d, sort_keys=True, separators=(",", ":"))`.
3. Compute `HMAC-SHA256(secret_bytes, canonical_json_bytes)`.
4. Hex-encode output (64 lowercase hex characters).
5. Receiver validates that `|ts - current_time| <= 60s` and rejects duplicate nonces.
