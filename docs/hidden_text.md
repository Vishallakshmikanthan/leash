# Leash: Hidden Text Scanner (N7)

## 1. Overview

The **Hidden Text Scanner** (`gates/hidden_text.py`) inspects commands, tool arguments, files read or modified by AI agents, and staged git commits for concealed text and evasion techniques:
- Invisible zero-width Unicode characters
- Bidirectional (BiDi) control overrides (Trojan Source attacks)
- Unicode Tag characters (invisible ASCII steganography channels)
- ANSI terminal escape sequences that conceal output or rewrite terminal lines
- Hidden HTML comments (`<!-- ... -->`) and Markdown comments (`[//]: # (...)`) containing prompt injection or shell payloads
- Obfuscated Base64 payloads concealed within comments
- Mixed-script homoglyphs spoofing Latin identifiers

---

## 2. Detected Pattern Taxonomy

| Pattern Category | Examples & Codepoints | Risk Severity | Primary Threat Vector |
|------------------|----------------------|---------------|------------------------|
| **BiDi Controls** | U+202E (RLO), U+202D (LRO), U+202A (LRE), U+202B (RLE), U+2066-U+2069 (Isolates) | **HIGH** | **Trojan Source (CVE-2021-42574)**: Reverses visual display order so on-screen code diverges from compiler/shell execution. |
| **Unicode Tags** | U+E0000 - U+E007F (Invisible Tag ASCII Range) | **HIGH** | **Invisible Prompt Steganography**: Encodes invisible ASCII instructions that hijack LLMs without human visibility. |
| **Concealed Instructions** | `<!-- SYSTEM PROMPT: ... -->`, `[//]: # (ignore previous...)`, Base64 in comments | **HIGH** | **Indirect Prompt Injection**: Hidden instructions in documentation or source comments manipulating the AI agent. |
| **ANSI Escape Sequences** | `\x1b[8m` (Conceal), `\x1b[2K`, `\r` line overwrites | **HIGH** / **MEDIUM** | **Terminal Evasion**: Hides executed command lines or rewrites terminal history. |
| **Zero-Width / Fillers** | U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ), U+FEFF (BOM), U+3164 (Hangul Filler) | **MEDIUM** | **Filter Bypass**: Disguises malicious keywords, evades string blocklists, or smuggles tokens. |
| **Homoglyphs** | Cyrillic `а`, `е`, `о`, `р`, `с`, `х` mixed into Latin identifiers | **MEDIUM** | **Identifier Spoofing**: Visually imitates safe commands or files (e.g., `cаt` vs `cat`). |

---

## 3. Reporting Structure

Every detection produces a `HiddenTextFinding` object containing:
- **File**: Affected file path or target string (`command`, `staged`, `README.md`, etc.).
- **Location**: Exact line and column offset (`file:line:col`).
- **Detected Pattern**: Pattern name and Unicode codepoint (`BiDi Control RLO (U+202E)`).
- **Risk Reason**: Specific explanation of the vulnerability and danger.
- **Snippet**: Clean visual preview highlighting concealed codepoints.

---

## 4. Subsystem Integrations

1. **Provenance Tracking (`gates/provenance_tracker.py`)**:
   - Files read containing hidden text taint the session with `flags=["hidden-text", ...]`.
   - Records `ProvenanceEvent` with `kind=ProvenanceKind.HIDDEN_TEXT_DETECTED`.
2. **Risk Engine (`daemon/policy_evaluator.py`)**:
   - `HiddenTextGate` denies quick allow for any action containing hidden text.
   - Triggers `R-TXT-BIDI-OVERRIDE`, `R-TXT-TAG-STEGANOGRAPHY`, `R-TXT-CONCEALED-INSTRUCTION`, or `R-TXT-HIDDEN-UNICODE`.
3. **Guard Alerts (`daemon/risk_explainer.py` & Android `OnDeviceRiskExplainer.kt`)**:
   - Generates Category 10 risk alerts displaying affected file, line location, detected pattern, and plain-English explanation.
   - Broadcasts `hidden_text_alert` over WebSocket to paired Android Guard devices.
4. **Audit Logging (`daemon/audit_logger.py`)**:
   - Appends structured `hidden_text_detected` event to `audit.jsonl` with file, line, pattern name, and risk reason.
5. **Agent Receipt (`daemon/receipt_builder.py`)**:
   - Summarizes hidden text detections under security and risk events with badge `👁️ HIDDEN TEXT`.
