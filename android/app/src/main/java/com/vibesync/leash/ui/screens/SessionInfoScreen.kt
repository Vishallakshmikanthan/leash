package com.vibesync.leash.ui.screens

import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vibesync.leash.data.model.*
import com.vibesync.leash.ui.theme.*
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SessionInfoScreen(
    sessionContext: SessionContext,
    guardStats: GuardStats,
    sessionActivity: SessionSummary? = null,
    feedItems: List<AuditFeedItem> = emptyList(),
    onRefreshActivity: () -> Unit = {},
    onRewind: (onSuccess: (String) -> Unit) -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var showRewindDialog by remember { mutableStateOf(false) }
    var activityFilter by remember { mutableStateOf("ALL") }

    // Combine timeline from server session activity or fallback to local feed items
    val timelineItems: List<SessionActivityItem> = remember(sessionActivity, feedItems) {
        if (sessionActivity != null && sessionActivity.timeline.isNotEmpty()) {
            sessionActivity.timeline
        } else {
            feedItems.map { item ->
                val req = item.bundle.request
                val assess = item.bundle.assessment
                val dec = item.decision
                val timeStr = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).format(Date(item.timestamp))
                SessionActivityItem(
                    action_id = req.id,
                    ts = item.timestamp / 1000,
                    timestamp_iso = timeStr,
                    kind = req.kind.name.lowercase(),
                    command = req.command ?: req.target_path ?: req.tool_name ?: "-",
                    target_path = req.target_path,
                    agent = req.agent,
                    worktree = req.worktree,
                    verdict = dec.verdict.name.lowercase(),
                    decision_method = dec.by.name.lowercase(),
                    risk_severity = assess.severity.name.lowercase(),
                    risk_category = assess.category,
                    risk_summary = assess.summary,
                    why = assess.why,
                    safer_alternative = assess.safer_alternative,
                    rule_ids = assess.rule_ids,
                    tainted = req.taint.tainted || assess.tainted_escalation,
                    taint_source = req.taint.source ?: assess.taint_source,
                    taint_line = req.taint.line ?: assess.taint_line,
                    snapshot_ref = sessionContext.lastSnapshotRef,
                    latency_ms = item.latencyMs.toDouble(),
                    execution_result = item.executionResult
                )
            }
        }
    }

    val filteredTimeline = remember(timelineItems, activityFilter) {
        when (activityFilter) {
            "ALLOWED" -> timelineItems.filter { it.verdict == "allow" }
            "BLOCKED" -> timelineItems.filter { it.verdict == "deny" }
            "RISKY" -> timelineItems.filter { it.risk_severity in listOf("high", "critical", "medium") }
            else -> timelineItems
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(LeashDarkBackground)
            .padding(16.dp)
            .verticalScroll(rememberScrollState())
    ) {
        // Overall Guard Metrics
        Text(
            text = "GUARD METRICS",
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold,
            color = LeashCyan,
            letterSpacing = 1.sp
        )
        Spacer(modifier = Modifier.height(10.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            MetricStatCard("INTERCEPTED", guardStats.totalIntercepted.toString(), LeashCyan, Modifier.weight(1f))
            MetricStatCard("APPROVED", guardStats.approvedCount.toString(), LeashPrimary, Modifier.weight(1f))
            MetricStatCard("DENIED", guardStats.deniedCount.toString(), LeashCritical, Modifier.weight(1f))
            MetricStatCard("TAINTED", guardStats.taintedCount.toString(), LeashWarning, Modifier.weight(1f))
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Session Information Card
        Card(
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = LeashSurface),
            border = androidx.compose.foundation.BorderStroke(1.dp, LeashBorder),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(18.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "ACTIVE SESSION CONTEXT",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = LeashTextSecondary,
                        letterSpacing = 1.sp
                    )
                    Surface(
                        color = LeashPrimary.copy(alpha = 0.15f),
                        shape = RoundedCornerShape(6.dp)
                    ) {
                        Text(
                            text = "ACTIVE",
                            color = LeashPrimary,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.ExtraBold,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                SessionDetailRow("Session ID", sessionContext.sessionId)
                SessionDetailRow("Agent Name", sessionContext.agentName)
                SessionDetailRow("Worktree Path", sessionContext.worktree)
                SessionDetailRow(
                    "Latest Git Snapshot",
                    sessionContext.lastSnapshotRef ?: "refs/leash/${sessionContext.sessionId}/snap_latest"
                )
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Provenance & Taint Status Card (F1)
        Card(
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = LeashSurface),
            border = androidx.compose.foundation.BorderStroke(
                1.5.dp,
                if (sessionContext.tainted) LeashCritical.copy(alpha = 0.7f) else LeashPrimary.copy(alpha = 0.5f)
            ),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(18.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = if (sessionContext.tainted) Icons.Default.Warning else Icons.Default.Shield,
                        contentDescription = "Provenance",
                        tint = if (sessionContext.tainted) LeashCritical else LeashPrimary,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = if (sessionContext.tainted) "SESSION TAINTED (RISK ELEVATED)" else "PROVENANCE: CLEAN",
                        color = if (sessionContext.tainted) LeashCritical else LeashPrimary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 12.sp,
                        letterSpacing = 0.8.sp
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                if (sessionContext.tainted) {
                    Text(
                        text = "The agent was exposed to untrusted external text in ${sessionContext.taintSource ?: "README.md"}${sessionContext.taintLine?.let { ":$it" } ?: ""}. All subsequent medium/high actions are escalated for mandatory human verification.",
                        color = LeashTextSecondary,
                        fontSize = 12.sp,
                        lineHeight = 18.sp
                    )
                } else {
                    Text(
                        text = "No untrusted text reads or prompt injection signatures detected in this session's execution tree.",
                        color = LeashTextSecondary,
                        fontSize = 12.sp
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // -------------------------------------------------------------------
        // SESSION ACTIVITY VIEW: What agent attempted, allowed/blocked & why
        // -------------------------------------------------------------------
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "SESSION-LEVEL ACTIVITY VIEW",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = LeashCyan,
                    letterSpacing = 1.sp
                )
                Text(
                    text = "What the agent attempted, decisions, and why",
                    fontSize = 11.sp,
                    color = LeashTextMuted
                )
            }
            IconButton(onClick = onRefreshActivity) {
                Icon(
                    imageVector = Icons.Default.Refresh,
                    contentDescription = "Refresh Activity",
                    tint = LeashCyan,
                    modifier = Modifier.size(20.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Filter Chips Row
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            listOf("ALL", "BLOCKED", "ALLOWED", "RISKY").forEach { filterTag ->
                val isSelected = activityFilter == filterTag
                FilterChip(
                    selected = isSelected,
                    onClick = { activityFilter = filterTag },
                    label = {
                        Text(
                            text = filterTag,
                            fontSize = 10.sp,
                            fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                        )
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = LeashSurfaceVariant,
                        selectedLabelColor = LeashCyan,
                        containerColor = LeashSurface,
                        labelColor = LeashTextSecondary
                    ),
                    border = FilterChipDefaults.filterChipBorder(
                        enabled = true,
                        selected = isSelected,
                        borderColor = if (isSelected) LeashCyan else LeashBorder
                    )
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        if (filteredTimeline.isEmpty()) {
            Card(
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = LeashSurface),
                border = androidx.compose.foundation.BorderStroke(1.dp, LeashBorder),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(20.dp).fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        imageVector = Icons.Default.CheckCircle,
                        contentDescription = null,
                        tint = LeashTextMuted,
                        modifier = Modifier.size(32.dp)
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "No Activity Recorded",
                        style = MaterialTheme.typography.titleSmall,
                        color = LeashTextSecondary
                    )
                    Text(
                        text = "Intercepted agent attempts and policy decisions will be logged here.",
                        fontSize = 11.sp,
                        color = LeashTextMuted
                    )
                }
            }
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                filteredTimeline.forEach { act ->
                    SessionActivityCard(item = act)
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // One-Tap Rewind Card (N4 Feature)
        Card(
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = LeashSurface),
            border = androidx.compose.foundation.BorderStroke(1.dp, LeashBorder),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(18.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Restore,
                        contentDescription = "Rewind",
                        tint = LeashPurple,
                        modifier = Modifier.size(22.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "ONE-TAP REWIND (GIT ROLLBACK)",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = LeashPurple,
                        letterSpacing = 1.sp
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Instantly roll back worktree files to the snapshot created prior to dangerous action approval. Repo files only.",
                    color = LeashTextSecondary,
                    fontSize = 12.sp,
                    lineHeight = 18.sp
                )

                Spacer(modifier = Modifier.height(14.dp))

                Button(
                    onClick = { showRewindDialog = true },
                    modifier = Modifier.fillMaxWidth().height(46.dp),
                    shape = RoundedCornerShape(10.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = LeashPurple,
                        contentColor = Color.Black
                    )
                ) {
                    Icon(Icons.Default.Undo, contentDescription = "Rollback")
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Roll Back to Pre-Action Snapshot", fontWeight = FontWeight.Bold)
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Task Scope Contract Card (N3 Feature)
        Card(
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = LeashSurface),
            border = androidx.compose.foundation.BorderStroke(1.dp, LeashBorder),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(18.dp)) {
                Text(
                    text = "TASK SCOPE CONTRACT (N3)",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = LeashCyan,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "Allowed Paths: ${sessionContext.allowedPaths.joinToString(", ")}",
                    fontSize = 12.sp,
                    color = LeashTextSecondary,
                    fontFamily = FontFamily.Monospace
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Allowed Commands: ${sessionContext.allowedCommands.joinToString(", ")}",
                    fontSize = 12.sp,
                    color = LeashTextSecondary,
                    fontFamily = FontFamily.Monospace
                )
            }
        }
        Spacer(modifier = Modifier.height(20.dp))

        // Agent Receipt Card (N5 Feature)
        val generatedReceipt = remember(sessionContext, guardStats, sessionActivity, timelineItems) {
            generateSessionMarkdownReceipt(sessionContext, guardStats, sessionActivity, timelineItems)
        }

        Card(
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = LeashSurface),
            border = androidx.compose.foundation.BorderStroke(1.dp, LeashPrimary.copy(alpha = 0.6f)),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(18.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Description,
                            contentDescription = "Agent Receipt",
                            tint = LeashPrimary,
                            modifier = Modifier.size(22.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "AGENT RECEIPT (PR-READY) (N5)",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            color = LeashPrimary,
                            letterSpacing = 1.sp
                        )
                    }
                    Surface(
                        color = LeashPrimary.copy(alpha = 0.15f),
                        shape = RoundedCornerShape(6.dp)
                    ) {
                        Text(
                            text = "PULL REQUEST",
                            color = LeashPrimary,
                            fontSize = 9.sp,
                            fontWeight = FontWeight.ExtraBold,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Generate and copy a clear Markdown receipt detailing actions, approvals, denials, blocked actions, changed files, added dependencies, and outcome for your Pull Request.",
                    color = LeashTextSecondary,
                    fontSize = 12.sp,
                    lineHeight = 18.sp
                )

                Spacer(modifier = Modifier.height(14.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = {
                            clipboardManager.setText(AnnotatedString(generatedReceipt))
                            Toast.makeText(context, "PR Receipt copied to clipboard!", Toast.LENGTH_SHORT).show()
                        },
                        modifier = Modifier.weight(1f).height(44.dp),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = LeashPrimary,
                            contentColor = Color.Black
                        )
                    ) {
                        Icon(Icons.Default.ContentCopy, contentDescription = "Copy", modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Copy PR Receipt", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    }

                    OutlinedButton(
                        onClick = { showReceiptDialog = true },
                        modifier = Modifier.weight(1f).height(44.dp),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = LeashCyan
                        ),
                        border = androidx.compose.foundation.BorderStroke(1.dp, LeashCyan)
                    ) {
                        Icon(Icons.Default.Visibility, contentDescription = "Preview", modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Preview", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    }
                }
            }
        }
    }

    // Rewind Confirmation Dialog
    if (showRewindDialog) {
        AlertDialog(
            onDismissRequest = { showRewindDialog = false },
            title = { Text("Confirm Git Worktree Rewind", color = LeashPurple) },
            text = {
                Text(
                    "This will restore the local git worktree to the pre-action snapshot ref (${sessionContext.lastSnapshotRef ?: "snap_latest"}). Uncommitted changes will be discarded.",
                    color = LeashTextPrimary,
                    fontSize = 13.sp
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showRewindDialog = false
                        onRewind { msg ->
                            Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = LeashPurple)
                ) {
                    Text("Execute Rewind", color = Color.Black, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showRewindDialog = false }) {
                    Text("Cancel", color = LeashTextSecondary)
                }
            },
            containerColor = LeashSurface
        )
    }

    // Agent Receipt Preview Dialog
    if (showReceiptDialog) {
        val receiptText = remember(sessionContext, guardStats, sessionActivity, timelineItems) {
            generateSessionMarkdownReceipt(sessionContext, guardStats, sessionActivity, timelineItems)
        }
        AlertDialog(
            onDismissRequest = { showReceiptDialog = false },
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Description, contentDescription = "Receipt", tint = LeashPrimary)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Agent Pull Request Receipt", color = LeashPrimary, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                }
            },
            text = {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 420.dp)
                        .verticalScroll(rememberScrollState())
                        .background(LeashDarkBackground, RoundedCornerShape(8.dp))
                        .padding(12.dp)
                ) {
                    Text(
                        text = receiptText,
                        color = LeashTextPrimary,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        lineHeight = 16.sp
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        clipboardManager.setText(AnnotatedString(receiptText))
                        showReceiptDialog = false
                        Toast.makeText(context, "PR Receipt copied to clipboard!", Toast.LENGTH_SHORT).show()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = LeashPrimary, contentColor = Color.Black)
                ) {
                    Icon(Icons.Default.ContentCopy, contentDescription = "Copy", modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Copy & Close", fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showReceiptDialog = false }) {
                    Text("Close", color = LeashTextSecondary)
                }
            },
            containerColor = LeashSurface
        )
    }
}

fun generateSessionMarkdownReceipt(
    sessionContext: SessionContext,
    guardStats: GuardStats,
    sessionActivity: SessionSummary?,
    timelineItems: List<SessionActivityItem>
): String {
    val total = timelineItems.size
    val allowed = timelineItems.count { it.verdict == "allow" }
    val blocked = timelineItems.count { it.verdict == "deny" }
    val taintedCount = timelineItems.count { it.tainted }
    val nowStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.US).format(Date())

    val blockedItems = timelineItems.filter { it.verdict == "deny" }

    val sb = StringBuilder()
    sb.append("# 🛡️ Leash Agent Session Receipt: `${sessionContext.sessionId}`\n\n")
    val outcomeBadge = if (blocked > 0) "🛡️ PROTECTED (RISKS MITIGATED)" else if (sessionContext.tainted) "⚠️ COMPLETED (TAINTED)" else "✅ CLEAN COMPLETION"
    sb.append("> **Session Outcome:** `$outcomeBadge`  \n")
    sb.append("> **Agent:** `${sessionContext.agentName}` | **Branch:** `leash/${sessionContext.sessionId}` | **Generated:** $nowStr\n\n")
    sb.append("---\n\n")

    sb.append("## 📊 Executive Summary\n\n")
    sb.append("| Metric | Count | Details |\n")
    sb.append("| :--- | :--- | :--- |\n")
    sb.append("| **Total Actions Evaluated** | `$total` | Intercepted at shell boundary |\n")
    sb.append("| **Approved / Allowed** | `$allowed` | Verified safe by policy |\n")
    sb.append("| **Denied / Blocked** | `$blocked` | Prevented dangerous operations |\n")
    sb.append("| **Tainted Invocations** | `$taintedCount` | Influenced by untrusted input |\n")
    sb.append("| **Worktree Isolation** | `1` | `${sessionContext.worktree}` |\n\n")

    sb.append("## 🎯 Session Scope & Environment\n\n")
    sb.append("- **Worktree Path:** `${sessionContext.worktree}`\n")
    sb.append("- **Allowed Paths:** `${sessionContext.allowedPaths.joinToString(", ")}`\n")
    sb.append("- **Allowed Commands:** `${sessionContext.allowedCommands.joinToString(", ")}`\n")
    sb.append("- **Provenance Status:** ${if (sessionContext.tainted) "⚠️ Tainted (${sessionContext.taintSource ?: "external input"})" else "✅ Clean"}\n\n")

    sb.append("## ⛔ Blocked Actions & Security Interventions\n\n")
    if (blockedItems.isNotEmpty()) {
        sb.append("| Time | Attempted Action | Risk | Gate | Why Blocked |\n")
        sb.append("| :--- | :--- | :--- | :--- | :--- |\n")
        for (b in blockedItems) {
            val cmdSan = b.command.replace("|", "\\|").replace("\n", " ")
            val whySan = b.why.replace("|", "\\|").replace("\n", " ")
            sb.append("| ${b.timestamp_iso.takeLast(8)} | `$cmdSan` | **${b.risk_severity.uppercase()}** | ${b.risk_category} | $whySan |\n")
        }
        sb.append("\n")
    } else {
        sb.append("✅ *Zero actions blocked. All agent operations complied with security policy.*\n\n")
    }

    sb.append("## 📝 Evaluated Actions Timeline\n\n")
    sb.append("<details><summary><b>Click to expand full action timeline ($total actions)</b></summary>\n\n")
    sb.append("| Time | Kind | Command / Target | Severity | Verdict | By | Reason |\n")
    sb.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
    for (act in timelineItems) {
        val cmdSan = act.command.replace("|", "\\|").replace("\n", " ")
        val whySan = act.why.replace("|", "\\|").replace("\n", " ")
        sb.append("| ${act.timestamp_iso.takeLast(8)} | ${act.kind} | `$cmdSan` | ${act.risk_severity.uppercase()} | **${act.verdict.uppercase()}** | ${act.decision_method} | $whySan |\n")
    }
    sb.append("\n</details>\n\n")

    sb.append("## 📋 Pull Request Reviewer Guidance\n\n")
    sb.append("- [x] Interception & safety verified on-device by Leash.\n")
    if (blocked > 0) {
        sb.append("- [ ] Review $blocked blocked action(s) for developer intent.\n")
    }
    if (sessionContext.tainted) {
        sb.append("- [ ] Note: Session was tainted; review changes for indirect prompt injection.\n")
    }
    sb.append("- [ ] Confirm no private keys or secrets are committed to the PR diff.\n\n")
    sb.append("---\n*Verified by **Leash** on-device AI safety layer. Zero cloud telemetry. PR-ready receipt.*")

    return sb.toString()
}

@Composable
fun SessionActivityCard(item: SessionActivityItem) {
    var expanded by remember { mutableStateOf(false) }

    val isAllowed = item.verdict == "allow"
    val verdictColor = if (isAllowed) LeashPrimary else LeashCritical
    val timeLabel = if (item.timestamp_iso.contains("T")) {
        item.timestamp_iso.substringAfter("T").take(8)
    } else {
        SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(item.ts * 1000))
    }

    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = LeashSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, if (item.tainted) LeashCritical.copy(alpha = 0.5f) else LeashBorder),
        modifier = Modifier
            .fillMaxWidth()
            .clickable { expanded = !expanded }
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            // Header Row: Time + Verdict Badge + Method Badge + Severity
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Surface(
                        color = verdictColor.copy(alpha = 0.15f),
                        shape = RoundedCornerShape(6.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, verdictColor.copy(alpha = 0.5f))
                    ) {
                        Text(
                            text = if (isAllowed) "ALLOWED" else "BLOCKED",
                            color = verdictColor,
                            fontWeight = FontWeight.ExtraBold,
                            fontSize = 10.sp,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(6.dp))

                    Surface(
                        color = LeashSurfaceVariant,
                        shape = RoundedCornerShape(6.dp)
                    ) {
                        Text(
                            text = item.decision_method.uppercase(),
                            color = LeashCyan,
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(6.dp))

                    Text(
                        text = item.risk_severity.uppercase(),
                        color = when (item.risk_severity.lowercase()) {
                            "critical", "high" -> LeashCritical
                            "medium" -> LeashWarning
                            else -> LeashPrimary
                        },
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold
                    )
                }

                Text(
                    text = timeLabel,
                    color = LeashTextMuted,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            // What the agent attempted
            Text(
                text = "Attempted: ${item.command}",
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
                color = Color(0xFF80CBC4),
                maxLines = if (expanded) Int.MAX_VALUE else 2
            )

            // Why Leash allowed or blocked
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "Why: ${item.why}",
                color = LeashTextSecondary,
                fontSize = 11.sp,
                lineHeight = 16.sp
            )

            // Taint Indicator
            if (item.tainted) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "⚠ Tainted from ${item.taint_source ?: "README.md"}${item.taint_line?.let { ":$it" } ?: ""}",
                    color = LeashCritical,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }

            // Execution Result Snippet
            item.execution_result?.let { exec ->
                Spacer(modifier = Modifier.height(6.dp))
                Surface(
                    color = if (exec.allowed) LeashSurfaceVariant else LeashCritical.copy(alpha = 0.1f),
                    shape = RoundedCornerShape(6.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = if (exec.allowed) "Execution: Exit ${exec.exit_code}" else "Execution: BLOCKED (${exec.blocked_reason ?: "Policy Denied"})",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (exec.allowed) LeashPrimary else LeashCritical
                        )
                        Text(
                            text = "${exec.duration_ms.toInt()}ms",
                            fontSize = 10.sp,
                            color = LeashTextMuted,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }

            // Expanded Metadata Details
            AnimatedVisibility(visible = expanded) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp)
                        .background(LeashDarkBackground, RoundedCornerShape(8.dp))
                        .padding(10.dp)
                ) {
                    Text(
                        text = "Agent: ${item.agent} | Worktree: ${item.worktree ?: "default"}",
                        fontSize = 11.sp,
                        color = LeashTextSecondary,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        text = "Category: ${item.risk_category}",
                        fontSize = 11.sp,
                        color = LeashPurple,
                        fontFamily = FontFamily.Monospace
                    )
                    item.safer_alternative?.takeIf { it.isNotBlank() && it != "None required." }?.let { alt ->
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Safer Alternative: $alt",
                            fontSize = 11.sp,
                            color = LeashCyan
                        )
                    }
                    item.execution_result?.stdout_snippet?.takeIf { it.isNotBlank() }?.let { out ->
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Output: $out",
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace,
                            color = LeashTextSecondary
                        )
                    }
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Action ID: ${item.action_id}",
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = LeashTextMuted
                    )
                }
            }
        }
    }
}

@Composable
fun MetricStatCard(label: String, value: String, color: Color, modifier: Modifier = Modifier) {
    Surface(
        color = LeashSurface,
        shape = RoundedCornerShape(12.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, LeashBorder),
        modifier = modifier
    ) {
        Column(
            modifier = Modifier.padding(vertical = 12.dp, horizontal = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = value,
                color = color,
                fontSize = 18.sp,
                fontWeight = FontWeight.ExtraBold,
                fontFamily = FontFamily.Monospace
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = label,
                color = LeashTextMuted,
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 0.5.sp
            )
        }
    }
}

@Composable
fun SessionDetailRow(label: String, value: String) {
    Column(modifier = Modifier.padding(vertical = 4.dp)) {
        Text(text = label, color = LeashTextMuted, fontSize = 10.sp, fontWeight = FontWeight.Bold)
        Text(
            text = value,
            color = LeashCyan,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace
        )
    }
}
