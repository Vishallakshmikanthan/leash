package com.vibesync.leash.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vibesync.leash.data.model.AuditFeedItem
import com.vibesync.leash.data.model.Severity
import com.vibesync.leash.data.model.Verdict
import com.vibesync.leash.ui.theme.*
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ActionFeedScreen(
    feedItems: List<AuditFeedItem>,
    modifier: Modifier = Modifier
) {
    var selectedFilter by remember { mutableStateOf("ALL") }

    val filteredItems = remember(feedItems, selectedFilter) {
        when (selectedFilter) {
            "ALLOWED" -> feedItems.filter { it.decision.verdict == Verdict.ALLOW }
            "DENIED" -> feedItems.filter { it.decision.verdict == Verdict.DENY }
            "CRITICAL" -> feedItems.filter {
                it.bundle.assessment.severity == Severity.HIGH || it.bundle.assessment.severity == Severity.CRITICAL
            }
            else -> feedItems
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(LeashDarkBackground)
            .padding(horizontal = 16.dp)
    ) {
        // Filter Chips Row
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            listOf("ALL", "ALLOWED", "DENIED", "CRITICAL").forEach { filterTag ->
                val isSelected = selectedFilter == filterTag
                FilterChip(
                    selected = isSelected,
                    onClick = { selectedFilter = filterTag },
                    label = {
                        Text(
                            text = filterTag,
                            fontSize = 11.sp,
                            fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                        )
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = LeashSurfaceVariant,
                        selectedLabelColor = LeashPrimary,
                        containerColor = LeashSurface,
                        labelColor = LeashTextSecondary
                    ),
                    border = FilterChipDefaults.filterChipBorder(
                        enabled = true,
                        selected = isSelected,
                        borderColor = if (isSelected) LeashPrimary else LeashBorder
                    )
                )
            }
        }

        if (filteredItems.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Default.History,
                        contentDescription = "No history",
                        tint = LeashTextMuted,
                        modifier = Modifier.size(48.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = "No Interceptions Recorded",
                        style = MaterialTheme.typography.titleSmall,
                        color = LeashTextSecondary
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Real agent actions will appear here in real time.",
                        style = MaterialTheme.typography.bodySmall,
                        color = LeashTextMuted
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxWidth().weight(1f),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = PaddingValues(bottom = 16.dp)
            ) {
                items(filteredItems, key = { it.id }) { item ->
                    FeedItemRow(item = item)
                }
            }
        }
    }
}

@Composable
fun FeedItemRow(item: AuditFeedItem) {
    val req = item.bundle.request
    val assessment = item.bundle.assessment
    val decision = item.decision

    var expanded by remember { mutableStateOf(false) }

    val verdictColor = if (decision.verdict == Verdict.ALLOW) LeashPrimary else LeashCritical
    val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
    val formattedTime = timeFormat.format(Date(item.timestamp))

    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = LeashSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, LeashBorder),
        modifier = Modifier
            .fillMaxWidth()
            .clickable { expanded = !expanded }
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            // Header Row: Verdict Badge + Severity Badge + Timestamp
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Surface(
                        color = verdictColor.copy(alpha = 0.2f),
                        shape = RoundedCornerShape(6.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, verdictColor.copy(alpha = 0.5f))
                    ) {
                        Text(
                            text = decision.verdict.name,
                            color = verdictColor,
                            fontWeight = FontWeight.ExtraBold,
                            fontSize = 10.sp,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = assessment.severity.name,
                        color = when (assessment.severity) {
                            Severity.CRITICAL, Severity.HIGH -> LeashCritical
                            Severity.MEDIUM -> LeashWarning
                            Severity.LOW -> LeashPrimary
                        },
                        fontWeight = FontWeight.Bold,
                        fontSize = 11.sp
                    )
                }

                Text(
                    text = "$formattedTime (${item.latencyMs}ms)",
                    color = LeashTextMuted,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Command / Tool Text
            val cmd = req.command ?: req.target_path ?: req.tool_name ?: "Unknown Action"
            Text(
                text = cmd,
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
                color = Color(0xFF80CBC4),
                maxLines = if (expanded) Int.MAX_VALUE else 2
            )

            // Taint Pill if applicable
            if (req.taint.tainted || assessment.tainted_escalation) {
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "⚠ Tainted from ${req.taint.source ?: "README.md"}${req.taint.line?.let { ":$it" } ?: ""}",
                    color = LeashCritical,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }

            // Expanded Details View
            AnimatedVisibility(visible = expanded) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 10.dp)
                        .background(LeashDarkBackground, RoundedCornerShape(8.dp))
                        .padding(10.dp)
                ) {
                    Text(
                        text = "Decided By: ${decision.by.name}${if (decision.by == com.vibesync.leash.data.model.DecidedBy.TIMEOUT) " (Fail-Closed Default)" else ""}",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Medium,
                        color = if (decision.by == com.vibesync.leash.data.model.DecidedBy.TIMEOUT) LeashWarning else LeashCyan
                    )
                    decision.note?.let {
                        Text(
                            text = "Note: $it",
                            fontSize = 11.sp,
                            color = LeashTextSecondary
                        )
                    }
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Category: ${assessment.category}",
                        fontSize = 11.sp,
                        color = LeashPurple,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        text = "Agent: ${req.agent} | Worktree: ${req.worktree ?: "default"}",
                        fontSize = 11.sp,
                        color = LeashTextSecondary,
                        fontFamily = FontFamily.Monospace
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Why: ${assessment.why}",
                        fontSize = 11.sp,
                        color = LeashTextSecondary
                    )
                    if (assessment.safer_alternative.isNotBlank() && assessment.safer_alternative != "None required.") {
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Alternative: ${assessment.safer_alternative}",
                            fontSize = 11.sp,
                            color = LeashCyan
                        )
                    }

                    // Execution Result details
                    item.executionResult?.let { exec ->
                        Spacer(modifier = Modifier.height(6.dp))
                        Surface(
                            color = if (exec.allowed) LeashSurfaceVariant else LeashCritical.copy(alpha = 0.1f),
                            shape = RoundedCornerShape(6.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(8.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(
                                        text = if (exec.allowed) "EXECUTION: SUCCESS (Exit ${exec.exit_code})" else "EXECUTION: BLOCKED",
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
                                exec.blocked_reason?.let { reason ->
                                    Spacer(modifier = Modifier.height(2.dp))
                                    Text(
                                        text = "Reason: $reason",
                                        fontSize = 11.sp,
                                        color = LeashCritical
                                    )
                                }
                                exec.stdout_snippet?.takeIf { it.isNotBlank() }?.let { snippet ->
                                    Spacer(modifier = Modifier.height(2.dp))
                                    Text(
                                        text = "Output: $snippet",
                                        fontSize = 10.sp,
                                        fontFamily = FontFamily.Monospace,
                                        color = LeashTextSecondary,
                                        maxLines = 3
                                    )
                                }
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Action ID: ${req.id}",
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = LeashTextMuted
                    )
                }
            }
        }
    }
}
