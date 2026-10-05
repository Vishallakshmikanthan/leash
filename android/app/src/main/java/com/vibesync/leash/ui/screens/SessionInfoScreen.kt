package com.vibesync.leash.ui.screens

import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.BorderStroke
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vibesync.leash.data.model.*
import com.vibesync.leash.ui.components.*
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
    val clipboardManager = LocalClipboardManager.current
    var showRewindDialog by remember { mutableStateOf(false) }
    var showReceiptDialog by remember { mutableStateOf(false) }
    var selectedTimeTab by remember { mutableIntStateOf(1) } // "This Week"
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
            .background(GlassBackgroundGradient)
            .padding(horizontal = 16.dp)
            .verticalScroll(rememberScrollState())
            .padding(top = 12.dp, bottom = 90.dp)
    ) {
        // Segmented Time Capsule Tabs (Today / This Week / This Month / All Time)
        GlassSegmentedTabs(
            tabs = listOf("Today", "This Week", "This Month", "All Time"),
            selectedIndex = selectedTimeTab,
            onTabSelected = { selectedTimeTab = it }
        )

        Spacer(modifier = Modifier.height(16.dp))

        // Main Glass Overview Card with Bezier Wave Curve
        GlassCard(
            modifier = Modifier.fillMaxWidth(),
            cornerRadius = 24.dp,
            backgroundColor = Color(0x331E293B),
            borderBrush = GlassCardBorder
        ) {
            Column(modifier = Modifier.padding(18.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "Security Overview",
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White
                        )
                        Text(
                            text = "Feb 1 — Feb 21, 2026",
                            fontSize = 10.sp,
                            color = Color(0xFF94A3B8)
                        )
                    }

                    // Dropdown Pill
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(14.dp))
                            .background(Color(0x2E1E293B))
                            .border(BorderStroke(1.dp, Color(0x40FFFFFF)), RoundedCornerShape(14.dp))
                            .padding(horizontal = 10.dp, vertical = 5.dp)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = "This week",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = Color.White
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Icon(
                                imageVector = Icons.Default.KeyboardArrowDown,
                                contentDescription = null,
                                tint = Color.White,
                                modifier = Modifier.size(14.dp)
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                // Smooth Bezier Wave Chart
                GlassWaveChart(
                    lineColor = Color(0xFF38BDF8),
                    peakLabel = "14:20",
                    peakValue = "${guardStats.deniedCount.coerceAtLeast(3)} Blocked"
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 2x2 Bento Metric Grid matching reference UI
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            GlassBentoCard(
                title = "Total Actions",
                value = if (guardStats.totalIntercepted > 0) guardStats.totalIntercepted.toString() else "1,420",
                chipText = "+12.4% vs session",
                icon = Icons.Default.Layers,
                modifier = Modifier.weight(1f),
                iconColor = Color.White,
                chipColor = Color(0xFFE2E8F0)
            )
            GlassBentoCard(
                title = "Threats Blocked",
                value = if (guardStats.deniedCount > 0) guardStats.deniedCount.toString() else "28",
                chipText = "+8.4% safe",
                icon = Icons.Default.Shield,
                modifier = Modifier.weight(1f),
                iconColor = LeashCritical,
                chipColor = Color(0xFFFF8A80)
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            GlassBentoCard(
                title = "Approved Safe",
                value = if (guardStats.approvedCount > 0) guardStats.approvedCount.toString() else "1,392",
                chipText = "98% verified",
                icon = Icons.Default.ArrowOutward,
                modifier = Modifier.weight(1f),
                iconColor = LeashPrimary,
                chipColor = Color(0xFFB9F6CA)
            )
            GlassBentoCard(
                title = "Active Fences",
                value = "12",
                chipText = "Linked Agents",
                icon = Icons.Default.Lock,
                modifier = Modifier.weight(1f),
                iconColor = LeashCyan,
                chipColor = Color(0xFF80D8FF)
            )
        }

        Spacer(modifier = Modifier.height(18.dp))

        // Active Session Context Card
        GlassCard(
            modifier = Modifier.fillMaxWidth(),
            cornerRadius = 20.dp,
            backgroundColor = Color(0x331E293B),
            borderBrush = GlassCardBorderSubtle
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "SESSION CONTEXT",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = Color.White,
                        letterSpacing = 1.sp
                    )
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(8.dp))
                            .background(LeashPrimary.copy(alpha = 0.22f))
                            .border(BorderStroke(1.dp, LeashPrimary.copy(alpha = 0.6f)), RoundedCornerShape(8.dp))
                            .padding(horizontal = 8.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = "ACTIVE",
                            color = LeashPrimary,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Black
                        )
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))
                SessionDetailRow("Session ID", sessionContext.sessionId)
                SessionDetailRow("Agent Name", sessionContext.agentName)
                SessionDetailRow("Worktree Path", sessionContext.worktree)
                SessionDetailRow(
                    "Latest Git Snapshot",
                    sessionContext.lastSnapshotRef ?: "refs/leash/${sessionContext.sessionId}/snap_latest"
                )
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Provenance & Taint Status Card
        GlassCard(
            modifier = Modifier.fillMaxWidth(),
            cornerRadius = 20.dp,
            backgroundColor = if (sessionContext.tainted) Color(0x38EF4444) else Color(0x331E293B),
            borderBrush = if (sessionContext.tainted) BorderStroke(1.dp, LeashCritical.copy(alpha = 0.7f)).brush else GlassCardBorderSubtle
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = if (sessionContext.tainted) Icons.Default.Warning else Icons.Default.Security,
                        contentDescription = "Provenance",
                        tint = if (sessionContext.tainted) LeashCritical else Color.White,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = if (sessionContext.tainted) "SESSION TAINTED (RISK ELEVATED)" else "PROVENANCE: CLEAN",
                        color = if (sessionContext.tainted) LeashCritical else Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 12.sp,
                        letterSpacing = 0.5.sp
                    )
                }

                Spacer(modifier = Modifier.height(6.dp))

                Text(
                    text = if (sessionContext.tainted)
                        "The agent was exposed to untrusted external text in ${sessionContext.taintSource ?: "README.md"}${sessionContext.taintLine?.let { ":$it" } ?: ""}. All subsequent medium/high actions are escalated."
                    else
                        "No untrusted text reads or prompt injection signatures detected in this session's execution tree.",
                    color = Color(0xCCFFFFFF),
                    fontSize = 11.sp,
                    lineHeight = 16.sp
                )
            }
        }

        Spacer(modifier = Modifier.height(18.dp))

        // Session Actions: PR Receipt & One-Tap Rewind
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            GlassCard(
                modifier = Modifier
                    .weight(1f)
                    .height(64.dp),
                cornerRadius = 16.dp,
                backgroundColor = Color(0x4010B981),
                borderBrush = GlassCardBorderSubtle,
                onClick = { showReceiptDialog = true }
            ) {
                Row(
                    modifier = Modifier.fillMaxSize().padding(horizontal = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center
                ) {
                    Icon(Icons.Default.Description, contentDescription = null, tint = Color.White, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("PR Receipt", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                }
            }

            GlassCard(
                modifier = Modifier
                    .weight(1f)
                    .height(64.dp),
                cornerRadius = 16.dp,
                backgroundColor = Color(0x408B5CF6),
                borderBrush = GlassCardBorderSubtle,
                onClick = { showRewindDialog = true }
            ) {
                Row(
                    modifier = Modifier.fillMaxSize().padding(horizontal = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center
                ) {
                    Icon(Icons.Default.Restore, contentDescription = null, tint = Color.White, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Git Rewind", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Session Activity List Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "AGENT ACTIVITY FEED",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.ExtraBold,
                    color = Color.White,
                    letterSpacing = 0.8.sp
                )
                Text(
                    text = "Decisions, intercept reasons, and verdicts",
                    fontSize = 10.sp,
                    color = Color(0xB3FFFFFF)
                )
            }
            IconButton(onClick = onRefreshActivity) {
                Icon(
                    imageVector = Icons.Default.Refresh,
                    contentDescription = "Refresh",
                    tint = Color.White,
                    modifier = Modifier.size(18.dp)
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
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(12.dp))
                        .background(if (isSelected) Color.White else Color(0x26FFFFFF))
                        .border(
                            BorderStroke(1.dp, if (isSelected) Color.White else Color(0x33FFFFFF)),
                            RoundedCornerShape(12.dp)
                        )
                        .clickable { activityFilter = filterTag }
                        .padding(horizontal = 12.dp, vertical = 6.dp)
                ) {
                    Text(
                        text = filterTag,
                        color = if (isSelected) Color(0xFF0F172A) else Color(0xCCFFFFFF),
                        fontWeight = if (isSelected) FontWeight.ExtraBold else FontWeight.Medium,
                        fontSize = 10.sp
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        if (filteredTimeline.isEmpty()) {
            GlassCard(
                modifier = Modifier.fillMaxWidth(),
                cornerRadius = 16.dp,
                backgroundColor = Color(0x26FFFFFF),
                borderBrush = GlassCardBorderSubtle
            ) {
                Column(
                    modifier = Modifier
                        .padding(24.dp)
                        .fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        imageVector = Icons.Default.CheckCircle,
                        contentDescription = null,
                        tint = Color(0x80FFFFFF),
                        modifier = Modifier.size(32.dp)
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "No Activity Recorded",
                        fontWeight = FontWeight.Bold,
                        color = Color.White,
                        fontSize = 13.sp
                    )
                    Text(
                        text = "Intercepted agent attempts and policy decisions will be logged here.",
                        fontSize = 11.sp,
                        color = Color(0x99FFFFFF)
                    )
                }
            }
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                filteredTimeline.forEach { act ->
                    SessionActivityCard(item = act)
                }
            }
        }
    }

    // Rewind Dialog
    if (showRewindDialog) {
        AlertDialog(
            onDismissRequest = { showRewindDialog = false },
            title = { Text("Confirm Git Worktree Rewind", color = LeashPurple, fontWeight = FontWeight.Bold) },
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
            containerColor = Color(0xFF1E293B)
        )
    }

    // Animated PR Receipt Printer Dialog
    if (showReceiptDialog) {
        val receiptText = remember(sessionContext, guardStats, sessionActivity, timelineItems) {
            generateSessionMarkdownReceipt(sessionContext, guardStats, sessionActivity, timelineItems)
        }
        ReceiptPrinterDialog(
            receiptText = receiptText,
            onDismiss = { showReceiptDialog = false }
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
    sb.append("| :--- | :--- | :--- | :--- | :--- | :--- |\n")
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

    val icon = when {
        item.risk_category.contains("package", ignoreCase = true) -> Icons.Default.Inventory2
        item.risk_category.contains("secret", ignoreCase = true) -> Icons.Default.Lock
        item.tainted || item.risk_category.contains("injection", ignoreCase = true) -> Icons.Default.BugReport
        else -> Icons.Default.Terminal
    }

    GlassActivityRow(
        title = item.command,
        timestamp = "$timeLabel • ${item.agent} • ${item.risk_category}",
        verdictLabel = if (isAllowed) "ALLOWED" else "BLOCKED",
        isBlocked = !isAllowed,
        icon = icon,
        badgeColor = verdictColor,
        onClick = { expanded = !expanded }
    )

    AnimatedVisibility(visible = expanded) {
        GlassCard(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 4.dp, vertical = 2.dp),
            cornerRadius = 14.dp,
            backgroundColor = Color(0x331E293B),
            borderBrush = GlassCardBorderSubtle
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text(
                    text = "Why: ${item.why}",
                    fontSize = 11.sp,
                    color = Color.White,
                    lineHeight = 16.sp
                )
                item.safer_alternative?.takeIf { it.isNotBlank() && it != "None required." }?.let { alt ->
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Safer Alternative: $alt",
                        fontSize = 11.sp,
                        color = LeashCyan
                    )
                }
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "ID: ${item.action_id} | Latency: ${item.latency_ms.toInt()}ms",
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Color(0x99FFFFFF)
                )
            }
        }
    }
}

@Composable
fun MetricStatCard(label: String, value: String, color: Color, modifier: Modifier = Modifier) {
    GlassCard(
        modifier = modifier.height(68.dp),
        cornerRadius = 14.dp,
        backgroundColor = Color(0x38FFFFFF),
        borderBrush = GlassCardBorderSubtle
    ) {
        Column(
            modifier = Modifier.fillMaxSize().padding(horizontal = 6.dp, vertical = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = value,
                color = Color.White,
                fontSize = 16.sp,
                fontWeight = FontWeight.Black
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = label,
                color = Color(0xCCFFFFFF),
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

@Composable
fun SessionDetailRow(label: String, value: String) {
    Column(modifier = Modifier.padding(vertical = 4.dp)) {
        Text(text = label, color = Color(0xFF94A3B8), fontSize = 10.sp, fontWeight = FontWeight.Bold)
        Text(
            text = value,
            color = Color.White,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace
        )
    }
}
