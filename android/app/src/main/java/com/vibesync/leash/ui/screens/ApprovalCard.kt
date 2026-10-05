package com.vibesync.leash.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import com.vibesync.leash.ui.components.GlassCard
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vibesync.leash.data.model.ActionBundle
import com.vibesync.leash.data.model.ActionKind
import com.vibesync.leash.data.model.DecidedBy
import com.vibesync.leash.data.model.RiskExplanation
import com.vibesync.leash.data.model.Severity
import com.vibesync.leash.data.engine.OnDeviceRiskExplainer
import com.vibesync.leash.ui.theme.*
import kotlinx.coroutines.delay

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ApprovalCard(
    bundle: ActionBundle,
    queueIndex: Int = 1,
    queueTotal: Int = 1,
    initialTimeoutSeconds: Int = 30,
    initialExplanation: RiskExplanation? = null,
    onNextInQueue: (() -> Unit)? = null,
    onPreviousInQueue: (() -> Unit)? = null,
    onApprove: (DecidedBy) -> Unit,
    onDeny: (String?) -> Unit,
    onTimeout: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val req = bundle.request
    val assessment = bundle.assessment

    val isHighOrCritical = assessment.severity == Severity.HIGH || assessment.severity == Severity.CRITICAL

    val severityColor = when (assessment.severity) {
        Severity.CRITICAL -> LeashCritical
        Severity.HIGH -> Color(0xFFFF5252)
        Severity.MEDIUM -> LeashWarning
        Severity.LOW -> LeashPrimary
    }

    var currentExplanation by remember(bundle.request.id, initialExplanation) {
        mutableStateOf(
            initialExplanation ?: OnDeviceRiskExplainer.getTemplateExplanation(
                command = req.command ?: req.target_path ?: "",
                category = assessment.category,
                severity = assessment.severity.name.lowercase(),
                context = mapOf(
                    "target_path" to req.target_path,
                    "taint_source" to (req.taint.source ?: assessment.taint_source),
                    "taint_line" to (req.taint.line ?: assessment.taint_line),
                    "existing_summary" to assessment.summary,
                    "existing_why" to assessment.why,
                    "existing_alternative" to assessment.safer_alternative,
                    "action_id" to req.id
                )
            )
        )
    }

    // Live Countdown Timer (Fail-Closed Default 30s)
    var remainingSeconds by remember(bundle.request.id) { mutableIntStateOf(initialTimeoutSeconds) }
    var isTimerPaused by remember(bundle.request.id) { mutableStateOf(false) }

    LaunchedEffect(bundle.request.id, isTimerPaused) {
        while (remainingSeconds > 0 && !isTimerPaused) {
            delay(1000L)
            remainingSeconds -= 1
            if (remainingSeconds <= 0) {
                onTimeout()
                break
            }
        }
    }

    val timeoutProgress by animateFloatAsState(
        targetValue = remainingSeconds.toFloat() / initialTimeoutSeconds.toFloat(),
        label = "timeoutProgress"
    )

    val timerColor by animateColorAsState(
        targetValue = when {
            remainingSeconds > 15 -> LeashPrimary
            remainingSeconds > 5 -> LeashWarning
            else -> LeashCritical
        },
        label = "timerColor"
    )

    var showDetails by remember { mutableStateOf(false) }
    var showDenyDialog by remember { mutableStateOf(false) }
    var showTapFallbackDialog by remember { mutableStateOf(false) }
    var denialReason by remember { mutableStateOf("") }

    val scrollState = rememberScrollState()

    GlassCard(
        cornerRadius = 24.dp,
        backgroundColor = Color(0xF20F172A),
        borderBrush = Brush.linearGradient(
            listOf(
                severityColor.copy(alpha = 0.9f),
                Color(0x33FFFFFF),
                severityColor.copy(alpha = 0.4f)
            )
        ),
        borderWidth = 1.5.dp,
        modifier = modifier
            .fillMaxWidth()
            .padding(16.dp)
    ) {
        Column(
            modifier = Modifier
                .padding(18.dp)
                .verticalScroll(scrollState)
        ) {
            // Header: Queue Navigation + Severity + Category
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
                        text = if (queueTotal > 1) "ACTION $queueIndex OF $queueTotal" else "PENDING ACTION",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = LeashTextSecondary,
                        letterSpacing = 1.sp
                    )

                    // Queue Arrow Navigation if multiple actions pending
                    if (queueTotal > 1) {
                        Spacer(modifier = Modifier.width(6.dp))
                        IconButton(
                            onClick = { onPreviousInQueue?.invoke() },
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(
                                Icons.Default.NavigateBefore,
                                contentDescription = "Previous Action",
                                tint = LeashCyan,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                        IconButton(
                            onClick = { onNextInQueue?.invoke() },
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(
                                Icons.Default.NavigateNext,
                                contentDescription = "Next Action",
                                tint = LeashCyan,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }
                }

                // Severity Badge
                Surface(
                    color = severityColor.copy(alpha = 0.18f),
                    shape = RoundedCornerShape(10.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, severityColor.copy(alpha = 0.6f))
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

            Spacer(modifier = Modifier.height(10.dp))

            // Timeout Bar & Demonstration Controls
            Surface(
                color = LeashDarkBackground,
                shape = RoundedCornerShape(10.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, LeashBorder.copy(alpha = 0.6f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.Timer,
                                contentDescription = "Timeout countdown",
                                tint = timerColor,
                                modifier = Modifier.size(15.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = if (isTimerPaused) "PAUSED: ${remainingSeconds}s" else "TIMEOUT: ${remainingSeconds}s (FAIL-CLOSED)",
                                color = timerColor,
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold
                            )
                        }

                        // Demo pause & extend buttons for live presentation
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            IconButton(
                                onClick = { isTimerPaused = !isTimerPaused },
                                modifier = Modifier.size(24.dp)
                            ) {
                                Icon(
                                    imageVector = if (isTimerPaused) Icons.Default.PlayArrow else Icons.Default.Pause,
                                    contentDescription = "Toggle Timer Pause",
                                    tint = LeashTextSecondary,
                                    modifier = Modifier.size(14.dp)
                                )
                            }
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(
                                text = "+30s",
                                color = LeashCyan,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier
                                    .clickable { remainingSeconds += 30 }
                                    .padding(horizontal = 4.dp, vertical = 2.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(6.dp))

                    LinearProgressIndicator(
                        progress = { timeoutProgress },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(4.dp),
                        color = timerColor,
                        trackColor = LeashSurfaceVariant,
                        strokeCap = androidx.compose.ui.graphics.StrokeCap.Round
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Category & Agent Metadata Row
            FlowRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                // Category Tag
                Surface(
                    color = LeashSurfaceVariant,
                    shape = RoundedCornerShape(8.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, LeashBorder)
                ) {
                    Text(
                        text = "CAT: ${formatCategory(assessment.category)}",
                        color = LeashPurple,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }

                // Action Kind Badge
                Surface(
                    color = LeashSurfaceVariant,
                    shape = RoundedCornerShape(8.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, LeashBorder)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        Icon(
                            imageVector = when (req.kind) {
                                ActionKind.SHELL -> Icons.Default.Terminal
                                ActionKind.INSTALL -> Icons.Default.Inventory2
                                ActionKind.FILE_READ -> Icons.Default.Visibility
                                ActionKind.FILE_EDIT -> Icons.Default.EditNote
                                ActionKind.GIT -> Icons.Default.Commit
                                ActionKind.TOOL_CALL -> Icons.Default.Build
                            },
                            contentDescription = null,
                            tint = LeashCyan,
                            modifier = Modifier.size(13.dp)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = req.kind.name,
                            color = LeashCyan,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                // Agent Identity
                Surface(
                    color = LeashSurfaceVariant,
                    shape = RoundedCornerShape(8.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, LeashBorder)
                ) {
                    Text(
                        text = "AGENT: ${req.agent}",
                        color = LeashTextPrimary,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }

                // Worktree Badge
                req.worktree?.let { wt ->
                    Surface(
                        color = LeashSurfaceVariant,
                        shape = RoundedCornerShape(8.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, LeashBorder)
                    ) {
                        Text(
                            text = "TREE: $wt",
                            color = LeashTextSecondary,
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Intercepted Action Box
            val actionText = req.command ?: req.target_path ?: req.tool_name ?: "Unknown Action"
            Surface(
                color = LeashDarkBackground,
                shape = RoundedCornerShape(12.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, LeashBorder),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "INTERCEPTED COMMAND",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = LeashTextMuted,
                            letterSpacing = 0.8.sp
                        )
                        IconButton(
                            onClick = {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                clipboard.setPrimaryClip(ClipData.newPlainText("Action Command", actionText))
                                Toast.makeText(context, "Command copied to clipboard", Toast.LENGTH_SHORT).show()
                            },
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.ContentCopy,
                                contentDescription = "Copy command",
                                tint = LeashTextSecondary,
                                modifier = Modifier.size(15.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = actionText,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 13.sp,
                        color = Color(0xFF80CBC4),
                        lineHeight = 18.sp
                    )

                    if (req.cwd.isNotBlank()) {
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "cwd: ${req.cwd}",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            color = LeashTextMuted
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
                    border = androidx.compose.foundation.BorderStroke(1.dp, LeashCritical.copy(alpha = 0.5f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.Warning,
                                contentDescription = "Taint Warning",
                                tint = LeashCritical,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "PROVENANCE TAINT DETECTED • ESCALATED",
                                color = LeashCritical,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.ExtraBold,
                                letterSpacing = 0.5.sp
                            )
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        val sourceInfo = "${req.taint.source ?: assessment.taint_source ?: "README.md"}${req.taint.line?.let { ":$it" } ?: assessment.taint_line?.let { ":$it" } ?: ""}"
                        Text(
                            text = "Action influenced by untrusted input: $sourceInfo. Untrusted prompt instructions can manipulate shell actions. Severity elevated by 1 level.",
                            color = LeashTextPrimary,
                            fontSize = 12.sp,
                            lineHeight = 16.sp
                        )

                        // Scope Flags if present
                        if (req.scope_flags.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(8.dp))
                            FlowRow(
                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                req.scope_flags.forEach { flag ->
                                    Surface(
                                        color = LeashDarkBackground,
                                        shape = RoundedCornerShape(6.dp),
                                        border = androidx.compose.foundation.BorderStroke(1.dp, LeashCritical.copy(alpha = 0.4f))
                                    ) {
                                        Text(
                                            text = flag,
                                            color = LeashCritical,
                                            fontSize = 10.sp,
                                            fontFamily = FontFamily.Monospace,
                                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Runaway Guard Alert Banner (N6 Feature)
            val isRunaway = assessment.category in listOf("runaway-behavior-detected", "runaway-guard") ||
                req.scope_flags.contains("runaway-behavior-detected")
            if (isRunaway) {
                Spacer(modifier = Modifier.height(12.dp))
                Surface(
                    color = Color(0xFFFF5722).copy(alpha = 0.15f),
                    shape = RoundedCornerShape(10.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFFFF5722).copy(alpha = 0.6f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.Loop,
                                contentDescription = "Runaway Guard Warning",
                                tint = Color(0xFFFF5722),
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "RUNAWAY GUARD • AGENT PAUSED",
                                color = Color(0xFFFF5722),
                                fontSize = 11.sp,
                                fontWeight = FontWeight.ExtraBold,
                                letterSpacing = 0.5.sp
                            )
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = if (assessment.why.isNotBlank()) assessment.why else "Repeated failing commands, edit loops, or execution cadence burst detected. Agent paused pending your decision.",
                            color = LeashTextPrimary,
                            fontSize = 12.sp,
                            lineHeight = 16.sp
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Explanation Mode Header Badge
            val isModelSource = currentExplanation.source == "model"
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Surface(
                    color = if (isModelSource) LeashCyan.copy(alpha = 0.15f) else LeashPrimary.copy(alpha = 0.15f),
                    shape = RoundedCornerShape(8.dp),
                    border = androidx.compose.foundation.BorderStroke(
                        1.dp,
                        if (isModelSource) LeashCyan.copy(alpha = 0.5f) else LeashPrimary.copy(alpha = 0.5f)
                    )
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = if (isModelSource) Icons.Default.SmartToy else Icons.Default.Bolt,
                            contentDescription = "Explanation Source",
                            tint = if (isModelSource) LeashCyan else LeashPrimary,
                            modifier = Modifier.size(13.dp)
                        )
                        Spacer(modifier = Modifier.width(5.dp))
                        Text(
                            text = if (isModelSource) "ON-DEVICE AI EXPLANATION" else "RULE-BASED EXPLANATION",
                            color = if (isModelSource) LeashCyan else LeashPrimary,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 0.5.sp
                        )
                    }
                }

                Text(
                    text = "Enforced by Rule Engine",
                    color = LeashTextMuted,
                    fontSize = 10.sp,
                    fontStyle = androidx.compose.ui.text.font.FontStyle.Italic
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            val displaySummary = currentExplanation.summary.ifBlank { assessment.summary }
            val displayWhy = currentExplanation.why.ifBlank { assessment.why }
            val displayAlternative = currentExplanation.saferAlternative.ifBlank { assessment.safer_alternative }

            // Concise Plain-Language Summary
            Text(
                text = displaySummary,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = LeashTextPrimary,
                lineHeight = 22.sp
            )

            Spacer(modifier = Modifier.height(6.dp))

            // Why It Matters / Danger Explanation
            Text(
                text = displayWhy,
                style = MaterialTheme.typography.bodyMedium,
                color = LeashTextSecondary,
                lineHeight = 20.sp
            )

            // Recommended Safer Alternative Box
            if (displayAlternative.isNotBlank() && displayAlternative != "None required.") {
                Spacer(modifier = Modifier.height(12.dp))
                Surface(
                    color = LeashSurfaceVariant,
                    shape = RoundedCornerShape(10.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, LeashCyan.copy(alpha = 0.3f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Icon(
                            imageVector = Icons.Default.Lightbulb,
                            contentDescription = "Safer alternative",
                            tint = LeashCyan,
                            modifier = Modifier
                                .size(18.dp)
                                .padding(top = 1.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = "RECOMMENDED SAFER ALTERNATIVE",
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                color = LeashCyan,
                                letterSpacing = 0.6.sp
                            )
                            Spacer(modifier = Modifier.height(3.dp))
                            Text(
                                text = displayAlternative,
                                fontSize = 12.sp,
                                color = LeashTextPrimary,
                                lineHeight = 17.sp
                            )
                        }
                    }
                }
            }

            // Expandable Technical Diagnostics & Rules
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
                    text = if (showDetails) "Hide Technical Diagnostics" else "View Rule Diagnostics & Signature",
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
                            text = "Rules Fired: ${assessment.rule_ids.joinToString(", ")}",
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = LeashTextSecondary
                        )
                    }
                    Text(
                        text = "Action ID: ${req.id}",
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = LeashTextMuted
                    )
                    Text(
                        text = "Session: ${req.session} | Nonce: ${req.nonce.take(8)}...",
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = LeashTextMuted
                    )
                    Text(
                        text = "Security: HMAC-SHA256 Signed & Freshness Verified",
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = LeashPrimary
                    )
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Action Buttons: Deny vs Approve
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
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

                // Approve Button (Biometric for High/Critical, Tap for Low/Medium)
                Button(
                    onClick = {
                        if (isHighOrCritical) {
                            onApprove(DecidedBy.BIOMETRIC)
                        } else {
                            onApprove(DecidedBy.TAP)
                        }
                    },
                    modifier = Modifier
                        .weight(1.35f)
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
                        text = if (isHighOrCritical) "Approve (Fingerprint)" else "Approve (Tap)",
                        fontWeight = FontWeight.Bold,
                        fontSize = 12.sp
                    )
                }
            }

            // High-risk Tap Fallback Link
            if (isHighOrCritical) {
                Spacer(modifier = Modifier.height(10.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { showTapFallbackDialog = true }
                        .padding(vertical = 4.dp),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.TouchApp,
                        contentDescription = "Tap Fallback",
                        tint = LeashTextSecondary,
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "Biometric unavailable? Use Tap Fallback",
                        color = LeashTextSecondary,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Medium
                    )
                }
            }
        }
    }

    // Denial Note & Reason Dialog
    if (showDenyDialog) {
        AlertDialog(
            onDismissRequest = { showDenyDialog = false },
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Block, contentDescription = null, tint = LeashCritical)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Block Action", color = LeashCritical, fontWeight = FontWeight.Bold)
                }
            },
            text = {
                Column {
                    Text(
                        "Block this command from executing in the agent's worktree? The agent will receive this feedback so it can adapt.",
                        color = LeashTextPrimary,
                        fontSize = 13.sp,
                        lineHeight = 18.sp
                    )
                    Spacer(modifier = Modifier.height(12.dp))

                    Text(
                        "Quick Reasons:",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = LeashTextSecondary
                    )
                    Spacer(modifier = Modifier.height(6.dp))

                    val quickReasons = listOf(
                        "Untrusted external script",
                        "Dangerous destructive command",
                        "Outside task scope",
                        "Typosquatted package"
                    )
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        quickReasons.forEach { reason ->
                            Surface(
                                color = if (denialReason == reason) LeashCritical.copy(alpha = 0.25f) else LeashDarkBackground,
                                shape = RoundedCornerShape(8.dp),
                                border = androidx.compose.foundation.BorderStroke(
                                    1.dp,
                                    if (denialReason == reason) LeashCritical else LeashBorder
                                ),
                                modifier = Modifier.clickable { denialReason = reason }
                            ) {
                                Text(
                                    text = reason,
                                    color = if (denialReason == reason) LeashCritical else LeashTextSecondary,
                                    fontSize = 10.sp,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))
                    OutlinedTextField(
                        value = denialReason,
                        onValueChange = { denialReason = it },
                        placeholder = { Text("Custom reason for agent...", fontSize = 12.sp) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        showDenyDialog = false
                        onDeny(if (denialReason.isNotBlank()) denialReason else "Blocked by developer via Guard")
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = LeashCritical)
                ) {
                    Text("Block Command", color = Color.White, fontWeight = FontWeight.Bold)
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

    // Tap Fallback Confirmation Dialog for High-Risk
    if (showTapFallbackDialog) {
        AlertDialog(
            onDismissRequest = { showTapFallbackDialog = false },
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Shield, contentDescription = null, tint = LeashWarning)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Tap Fallback Authorization", color = LeashWarning, fontWeight = FontWeight.Bold)
                }
            },
            text = {
                Column {
                    Text(
                        "This action carries ${assessment.severity.name} severity. Are you sure you want to approve with screen tap instead of biometric fingerprint verification?",
                        color = LeashTextPrimary,
                        fontSize = 13.sp,
                        lineHeight = 18.sp
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        "This will be recorded in the audit log as 'Decided by TAP (Fallback)'.",
                        color = LeashTextSecondary,
                        fontSize = 11.sp
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        showTapFallbackDialog = false
                        onApprove(DecidedBy.TAP)
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = LeashWarning, contentColor = Color.Black)
                ) {
                    Text("Confirm Tap Approval", fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showTapFallbackDialog = false }) {
                    Text("Cancel", color = LeashTextSecondary)
                }
            },
            containerColor = LeashSurface
        )
    }
}

private fun formatCategory(category: String): String {
    return category.split("-", "_").joinToString(" ") { word ->
        word.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
    }
}
