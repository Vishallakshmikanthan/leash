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
