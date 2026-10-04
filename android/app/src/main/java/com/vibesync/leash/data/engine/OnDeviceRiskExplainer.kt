package com.vibesync.leash.data.engine

import com.vibesync.leash.data.model.ActionRequest
import com.vibesync.leash.data.model.RiskAssessment
import com.vibesync.leash.data.model.RiskExplanation
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject

/**
 * OnDeviceRiskExplainer - On-device explanation engine for Android Guard.
 * Provides immediate plain-language template fallbacks across all risk categories
 * and coordinates asynchronous model inference without delaying the initial security verdict.
 */
object OnDeviceRiskExplainer {

    private const val DEFAULT_TIMEOUT_MS = 1500L

    fun getTemplateExplanation(
        command: String,
        category: String,
        severity: String = "low",
        context: Map<String, Any?> = emptyMap()
    ): RiskExplanation {
        val cmd = command.trim()
        val cat = category.lowercase()
        val target = context["target_path"] as? String ?: extractTarget(cmd)
        val taintSource = context["taint_source"] as? String
        val taintLine = context["taint_line"]?.toString()
        val lineStr = if (taintLine != null) ":$taintLine" else ""

        val existingSummary = context["existing_summary"] as? String
        val existingWhy = context["existing_why"] as? String
        var existingAlt = context["existing_alternative"] as? String
        if (existingAlt == "None needed.") existingAlt = null

        val summary: String
        val why: String
        val saferAlt: String

        when {
            // Category 1: Remote Script Execution
            cat in listOf("remote-script-execution", "r-net-pipe-exec") -> {
                val (fetcher, interp) = extractFetcherAndInterpreter(cmd)
                summary = existingSummary ?: "Piping unverified remote content from $fetcher directly into $interp."
                why = existingWhy ?: "Executing uninspected remote code bypasses local verification and can immediately compromise host credentials and system integrity."
                saferAlt = existingAlt ?: "Download script with `$fetcher -O <file>`, inspect code manually, then execute."
            }

            // Category 2: Destructive File Operations
            cat in listOf("destructive-file-operations", "destructive-deletion", "r-fs-root-rm", "r-fs-recursive-rm") -> {
                summary = existingSummary ?: "Recursive deletion targeting directory or system files: `$target`."
                why = existingWhy ?: "Irreversibly removes files and directories without recycling or confirmation, which can destroy project code or system assets."
                saferAlt = existingAlt ?: "Inspect files with `git status` or remove specific targets rather than `$target`."
            }

            // Category 3: Forceful Git Operations
            cat in listOf("forceful-git-operations", "force-git", "r-git-force-push", "r-git-hard-reset") -> {
                if (cmd.contains("push", ignoreCase = true)) {
                    summary = existingSummary ?: "Force-pushing local changes to remote repository branch."
                    why = existingWhy ?: "Overwriting remote history destroys unmerged commits from collaborators on shared branches."
                    saferAlt = existingAlt ?: "Use `git push --force-with-lease` or pull and rebase before pushing."
                } else {
                    summary = existingSummary ?: "Hard resetting git working tree and index."
                    why = existingWhy ?: "Discards all uncommitted changes and local worktree modifications permanently."
                    saferAlt = existingAlt ?: "Use `git stash` to preserve modifications before changing git HEAD state."
                }
            }

            // Category 4: Secret Exposure & Canary Credentials
            cat in listOf("secret-exposure", "canary-touched", "r-secret-read", "r-secret-canary") -> {
                summary = existingSummary ?: "Reading sensitive or private credential file: `$target`."
                why = existingWhy ?: "Exposing secret tokens, private keys, or credentials prints sensitive data into command output buffers and LLM context history."
                saferAlt = existingAlt ?: "Reference environment variables directly instead of printing `$target` contents."
            }

            // Category 5: Package Installation & Supply Chain
            cat in listOf("package-install", "package-gate", "r-pkg-install", "r-pkg-typosquat") -> {
                val pkg = context["package_name"] as? String ?: target
                summary = existingSummary ?: "Installing package `$pkg` from public registry."
                why = existingWhy ?: "External packages execute arbitrary pre-install lifecycle scripts and may contain typosquatted or hijacked malicious dependencies."
                saferAlt = existingAlt ?: "Verify package spelling `$pkg` and inspect dependencies in lockfile before installing."
            }

            // Category 6: Sensitive File Changes
            cat in listOf("sensitive-file-changes", "system-config-tamper") -> {
                summary = existingSummary ?: "Attempting to modify system or host configuration: `$target`."
                why = existingWhy ?: "Modifying operating system files can alter network routing, DNS resolution, or user access controls."
                saferAlt = existingAlt ?: "Confine edits to project repository files instead of modifying `$target`."
            }

            // Category 7: Permission Changes
            cat in listOf("permission-changes", "r-perm-chmod-broad") -> {
                val prefix = if (cmd.length > 40) cmd.take(40) + "..." else cmd
                summary = existingSummary ?: "Broadening filesystem permissions with command `$prefix`."
                why = existingWhy ?: "Granting unrestricted read/write/execute rights creates privilege escalation vectors for other processes."
                saferAlt = existingAlt ?: "Apply least-privilege permission masks such as `chmod 755` or `chmod 644`."
            }

            // Category 8: Outbound Data Transfer
            cat in listOf("outbound-data-transfer", "r-net-outbound") -> {
                val prefix = if (cmd.length > 45) cmd.take(45) + "..." else cmd
                summary = existingSummary ?: "Transmitting data to external network endpoint: `$prefix`."
                why = existingWhy ?: "Unapproved network egress can exfiltrate local source code, environment secrets, or establish reverse shells."
                saferAlt = existingAlt ?: "Use local mock servers or request explicit network endpoint authorization."
            }

            // Category 9: Untrusted Text Influence (Prompt Injection)
            cat in listOf("untrusted-text-influence", "prompt-injection", "r-taint-influence") -> {
                val src = taintSource ?: "untrusted documentation"
                val prefix = if (cmd.length > 35) cmd.take(35) + "..." else cmd
                summary = existingSummary ?: "Action triggered after agent read untrusted content from `$src$lineStr`."
                why = existingWhy ?: "External text in `$src` may contain hidden prompt injection instructions attempting to hijack the agent to run dangerous commands."
                saferAlt = existingAlt ?: "Verify that `$prefix` aligns with your original task rather than instructions in `$src`."
            }

            // Category 10: Hidden Text & Unicode Evasion
            cat in listOf("hidden-text-detected", "hidden-unicode", "hidden-text") -> {
                val loc = context["location"] as? String ?: target.ifEmpty { "file" }
                val pat = context["pattern"] as? String ?: "invisible Unicode or bidirectional control characters"
                summary = existingSummary ?: "Concealed text or control characters detected in `$loc`."
                why = existingWhy ?: "Detected `$pat`. Invisible codepoints or hidden comments disguise malicious code (Trojan Source) or inject covert instructions."
                saferAlt = existingAlt ?: "Inspect file in raw byte mode, strip concealed characters, and verify source before proceeding."
            }

            // Category 11: Scope Violations / Task Contract Drift
            cat in listOf("scope-violations", "scope-drift", "r-scope-violation") -> {
                summary = existingSummary ?: "Command or path `$target` drifts outside declared session task scope."
                why = existingWhy ?: "The agent is executing outside the boundaries set at session start, risking unintended system impact."
                saferAlt = existingAlt ?: "Update allowed paths and commands in session scope contract before running."
            }

            // Category 12: Runaway Behavior / Failure Loops
            cat in listOf("runaway-behavior-detected", "runaway-guard") -> {
                val prefix = if (cmd.length > 35) cmd.take(35) + "..." else cmd
                summary = existingSummary ?: "Agent is stuck in an execution failure loop with command `$prefix`."
                why = existingWhy ?: "Consecutive failures indicate the agent is thrashing, which drains rate limits and risks file corruption."
                saferAlt = existingAlt ?: "Interrupt loop, review error message, and provide corrective instructions to agent."
            }

            // Category 13: Rewind / Snapshot Rollback
            cat in listOf("rewind", "r-rewind") -> {
                val snap = context["snapshot_ref"] as? String ?: "latest pre-action snapshot"
                summary = existingSummary ?: "Restoring git worktree state back to `$snap`."
                why = existingWhy ?: "Rolling back discards uncommitted work in the worktree and resets repository files to the snapshot."
                saferAlt = existingAlt ?: "Inspect current worktree diff before executing rollback."
            }

            // Default / Normal Development
            else -> {
                val prefix = if (cmd.length > 45) cmd.take(45) + "..." else cmd
                summary = existingSummary ?: "Executing standard development command: `$prefix`."
                why = existingWhy ?: "Standard development command matching normal repository workflow."
                saferAlt = existingAlt ?: "None required."
            }
        }

        return RiskExplanation(
            summary = summary,
            why = why,
            saferAlternative = saferAlt,
            source = "template",
            category = category,
            severity = severity,
            actionId = context["action_id"] as? String
        )
    }

    suspend fun explain(
        command: String,
        category: String,
        severity: String = "low",
        context: Map<String, Any?> = emptyMap(),
        modelInferenceFn: (suspend (String) -> String?)? = null,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS
    ): RiskExplanation {
        val startTime = System.currentTimeMillis()
        val template = getTemplateExplanation(command, category, severity, context)

        if (modelInferenceFn == null) {
            val latency = (System.currentTimeMillis() - startTime).toFloat()
            return template.copy(latencyMs = latency)
        }

        return try {
            val prompt = buildPrompt(command, category, severity, context)
            val rawOutput = withTimeoutOrNull(timeoutMs) {
                modelInferenceFn(prompt)
            }

            val latency = (System.currentTimeMillis() - startTime).toFloat()
            if (rawOutput != null) {
                val parsed = parseModelOutput(rawOutput)
                if (parsed != null) {
                    return RiskExplanation(
                        summary = parsed.optString("summary", template.summary),
                        why = parsed.optString("why", template.why),
                        saferAlternative = parsed.optString("safer_alternative", template.saferAlternative),
                        source = "model",
                        latencyMs = latency,
                        category = category,
                        severity = severity,
                        actionId = context["action_id"] as? String
                    )
                }
            }
            template.copy(latencyMs = latency)
        } catch (_: Exception) {
            val latency = (System.currentTimeMillis() - startTime).toFloat()
            template.copy(latencyMs = latency)
        }
    }

    private fun buildPrompt(command: String, category: String, severity: String, context: Map<String, Any?>): String {
        val target = context["target_path"] as? String
        val taint = context["taint_source"] as? String
        return "Explain this risky action for Leash bodyguard:\n" +
            "Command: $command\n" +
            "Category: $category\n" +
            "Severity: $severity\n" +
            (if (target != null) "Target: $target\n" else "") +
            (if (taint != null) "Taint: $taint\n" else "") +
            "Return JSON: {\"summary\":\"...\",\"why\":\"...\",\"safer_alternative\":\"...\"}"
    }

    private fun parseModelOutput(raw: String): JSONObject? {
        val trimmed = raw.trim()
        val cleaned = if (trimmed.startsWith("```")) {
            trimmed.lines().filterNot { it.startsWith("```") }.joinToString("\n").trim()
        } else trimmed
        return try {
            val obj = JSONObject(cleaned)
            if (obj.has("summary") && obj.has("why") && obj.has("safer_alternative")) {
                obj
            } else null
        } catch (_: Exception) {
            null
        }
    }

    private fun extractTarget(command: String): String {
        val tokens = command.trim().split("\\s+".toRegex())
        for (tok in tokens.reversed()) {
            if (!tok.startsWith("-") && tok !in listOf("|", "&&", ";", ">", "<")) {
                return tok
            }
        }
        return "target resource"
    }

    private fun extractFetcherAndInterpreter(command: String): Pair<String, String> {
        val lower = command.lowercase()
        val fetcher = if (lower.contains("curl")) "curl" else if (lower.contains("wget")) "wget" else "downloader"
        val interp = if (lower.contains("sh")) "sh" else if (lower.contains("bash")) "bash" else if (lower.contains("python")) "python" else "shell"
        return Pair(fetcher, interp)
    }
}
