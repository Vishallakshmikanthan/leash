package com.vibesync.leash.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
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
import com.vibesync.leash.data.model.ActionBundle
import com.vibesync.leash.data.model.Severity
import com.vibesync.leash.ui.theme.*

@Composable
fun ApprovalCard(
    bundle: ActionBundle,
    queueIndex: Int = 1,
    queueTotal: Int = 1,
    onApprove: () -> Unit,
    onDeny: (String?) -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val req = bundle.request
    val assessment = bundle.assessment

    val severityColor = when (assessment.severity) {
        Severity.CRITICAL -> LeashCritical
        Severity.HIGH -> LeashCritical
        Severity.MEDIUM -> LeashWarning
        Severity.LOW -> LeashPrimary
    }

    var showDetails by remember { mutableStateOf(false) }
    var showDenyDialog by remember { mutableStateOf(false) }
    var denialReason by remember { mutableStateOf("") }

    Card(
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = LeashSurface),
        elevation = CardDefaults.cardElevation(defaultElevation = 8.dp),
        modifier = modifier
            .fillMaxWidth()
            .padding(16.dp)
            .border(
                width = 1.5.dp,
                color = severityColor.copy(alpha = 0.8f),
                shape = RoundedCornerShape(20.dp)
            )
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            // Header: Queue indicator + Severity Pill
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(10.dp)
                            .background(severityColor, CircleShape)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = if (queueTotal > 1) "ACTION $queueIndex OF $queueTotal" else "PENDING APPROVAL",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = LeashTextSecondary,
                        letterSpacing = 1.sp
                    )
                }

                Surface(
                    color = severityColor.copy(alpha = 0.18f),
                    shape = RoundedCornerShape(10.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, severityColor.copy(alpha = 0.5f))
                ) {
                    Text(
                        text = assessment.severity.name,
                        color = severityColor,
                        fontWeight = FontWeight.ExtraBold,
                        fontSize = 11.sp,
                        letterSpacing = 0.8.sp,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Agent & Worktree Metadata Pills
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Surface(
                    color = LeashSurfaceVariant,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(
                        text = "AGENT: ${req.agent}",
                        color = LeashCyan,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }
                req.worktree?.let { wt ->
                    Surface(
                        color = LeashSurfaceVariant,
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text(
                            text = wt,
                            color = LeashTextSecondary,
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Action / Command Box
            val actionText = req.command ?: req.target_path ?: req.tool_name ?: "Unknown Action"
            Surface(
                color = LeashDarkBackground,
                shape = RoundedCornerShape(12.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, LeashBorder),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = actionText,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 13.sp,
                        color = Color(0xFF80CBC4),
                        modifier = Modifier.weight(1f)
                    )
                    IconButton(
                        onClick = {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            clipboard.setPrimaryClip(ClipData.newPlainText("Action Command", actionText))
                            Toast.makeText(context, "Command copied", Toast.LENGTH_SHORT).show()
                        },
                        modifier = Modifier.size(28.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.ContentCopy,
                            contentDescription = "Copy command",
                            tint = LeashTextSecondary,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
            }

            // Provenance / Taint Alert Banner (F1 Feature)
            if (assessment.tainted_escalation || req.taint.tainted) {
                Spacer(modifier = Modifier.height(12.dp))
                Surface(
                    color = LeashCritical.copy(alpha = 0.14f),
                    shape = RoundedCornerShape(10.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, LeashCritical.copy(alpha = 0.4f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Warning,
                            contentDescription = "Taint Warning",
                            tint = LeashCritical,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Tainted: Influenced by untrusted ${req.taint.source ?: "README.md"}${req.taint.line?.let { ":$it" } ?: ""}",
                            color = LeashCritical,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Summary Explanation
            Text(
                text = assessment.summary,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = LeashTextPrimary
            )

            Spacer(modifier = Modifier.height(6.dp))

            // Why Danger Explanation
            Text(
                text = assessment.why,
                style = MaterialTheme.typography.bodyMedium,
                color = LeashTextSecondary,
                lineHeight = 20.sp
            )

            // Safer Alternative Box
            if (assessment.safer_alternative.isNotBlank() && assessment.safer_alternative != "None required.") {
                Spacer(modifier = Modifier.height(12.dp))
                Surface(
                    color = LeashSurfaceVariant,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(10.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Icon(
                            imageVector = Icons.Default.Lightbulb,
                            contentDescription = "Safer alternative",
                            tint = LeashCyan,
                            modifier = Modifier.size(16.dp).padding(top = 2.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Text(
                                text = "RECOMMENDED ALTERNATIVE",
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                color = LeashCyan,
                                letterSpacing = 0.6.sp
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = assessment.safer_alternative,
                                fontSize = 12.sp,
                                color = LeashTextPrimary
                            )
                        }
                    }
                }
            }

            // Expandable Technical Rules and IDs
            Spacer(modifier = Modifier.height(10.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { showDetails = !showDetails }
                    .padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = if (showDetails) "Hide Technical Diagnostics" else "View Rule Diagnostics",
                    fontSize = 12.sp,
                    color = LeashCyan,
                    fontWeight = FontWeight.Medium
                )
                Icon(
                    imageVector = if (showDetails) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = "Toggle diagnostics",
                    tint = LeashCyan,
                    modifier = Modifier.size(18.dp)
                )
            }

            AnimatedVisibility(visible = showDetails) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(LeashDarkBackground, RoundedCornerShape(8.dp))
                        .padding(10.dp)
                ) {
                    Text(
                        text = "Category: ${assessment.category}",
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = LeashTextSecondary
                    )
                    if (assessment.rule_ids.isNotEmpty()) {
                        Text(
                            text = "Triggered Rules: ${assessment.rule_ids.joinToString(", ")}",
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = LeashTextSecondary
                        )
                    }
                    Text(
                        text = "Action ID: ${req.id} | Session: ${req.session}",
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = LeashTextMuted
                    )
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Action Decision Buttons: Deny vs Approve
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // Deny Button
                OutlinedButton(
                    onClick = { showDenyDialog = true },
                    modifier = Modifier
                        .weight(1f)
                        .height(48.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = LeashCritical
                    ),
                    border = androidx.compose.foundation.BorderStroke(1.5.dp, LeashCritical)
                ) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Deny",
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Deny", fontWeight = FontWeight.Bold)
                }

                // Approve Button (Biometric requirement for High/Critical)
                val isHighOrCritical = assessment.severity == Severity.HIGH || assessment.severity == Severity.CRITICAL
                Button(
                    onClick = onApprove,
                    modifier = Modifier
                        .weight(1.3f)
                        .height(48.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = LeashPrimary,
                        contentColor = Color.Black
                    )
                ) {
                    Icon(
                        imageVector = if (isHighOrCritical) Icons.Default.Fingerprint else Icons.Default.Check,
                        contentDescription = "Approve",
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = if (isHighOrCritical) "Approve (Fingerprint)" else "Approve",
                        fontWeight = FontWeight.Bold,
                        fontSize = 13.sp
                    )
                }
            }
        }
    }

    // Optional Denial Note Dialog
    if (showDenyDialog) {
        AlertDialog(
            onDismissRequest = { showDenyDialog = false },
            title = { Text("Confirm Action Denial", color = LeashCritical) },
            text = {
                Column {
                    Text(
                        "Block this command from executing in the agent's worktree?",
                        color = LeashTextPrimary,
                        fontSize = 14.sp
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    OutlinedTextField(
                        value = denialReason,
                        onValueChange = { denialReason = it },
                        placeholder = { Text("Optional feedback reason for agent...") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        showDenyDialog = false
                        onDeny(if (denialReason.isNotBlank()) denialReason else null)
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = LeashCritical)
                ) {
                    Text("Block Command", color = Color.White)
                }
            },
            dismissButton = {
                TextButton(onClick = { showDenyDialog = false }) {
                    Text("Cancel", color = LeashTextSecondary)
                }
            },
            containerColor = LeashSurface
        )
    }
}
