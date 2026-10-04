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
