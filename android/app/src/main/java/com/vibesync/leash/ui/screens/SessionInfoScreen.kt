package com.vibesync.leash.ui.screens

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vibesync.leash.data.model.GuardStats
import com.vibesync.leash.data.model.SessionContext
import com.vibesync.leash.ui.theme.*

@Composable
fun SessionInfoScreen(
    sessionContext: SessionContext,
    guardStats: GuardStats,
    onRewind: (onSuccess: (String) -> Unit) -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var showRewindDialog by remember { mutableStateOf(false) }

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
