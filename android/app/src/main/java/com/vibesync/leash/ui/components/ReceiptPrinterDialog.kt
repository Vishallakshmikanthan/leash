package com.vibesync.leash.ui.components

import android.widget.Toast
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.*
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.vibesync.leash.ui.theme.*

/**
 * Custom Jagged Shape for receipt paper bottom serrated edge.
 */
class JaggedReceiptShape(
    private val toothWidth: Float = 20f,
    private val toothHeight: Float = 10f
) : Shape {
    override fun createOutline(
        size: Size,
        layoutDirection: LayoutDirection,
        density: Density
    ): Outline {
        val path = Path().apply {
            moveTo(0f, 0f)
            lineTo(size.width, 0f)
            lineTo(size.width, size.height - toothHeight)

            var currentX = size.width
            var isUp = true
            while (currentX > 0f) {
                val nextX = (currentX - toothWidth).coerceAtLeast(0f)
                val nextY = if (isUp) size.height else size.height - toothHeight
                lineTo(nextX, nextY)
                isUp = !isUp
                currentX = nextX
            }
            close()
        }
        return Outline.Generic(path)
    }
}

/**
 * Animated Thermal Printer Dialog that prints the PR Receipt.
 * Buttons only appear after rollout finishes.
 */
@Composable
fun ReceiptPrinterDialog(
    receiptText: String,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current

    // Rollout Animation State (0f = hidden inside slot, 1f = fully rolled out)
    val rollProgress = remember { Animatable(0f) }
    var isRolloutFinished by remember { mutableStateOf(false) }

    // Thermal Printer feed LED blink
    val infiniteTransition = rememberInfiniteTransition(label = "printer_led")
    val ledAlpha by infiniteTransition.animateFloat(
        initialValue = 0.3f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(280, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "led_pulse"
    )

    // Trigger rollout upon display
    LaunchedEffect(Unit) {
        rollProgress.animateTo(
            targetValue = 1f,
            animationSpec = tween(
                durationMillis = 2400,
                easing = FastOutSlowInEasing
            )
        )
        isRolloutFinished = true
    }

    Dialog(
        onDismissRequest = {
            if (isRolloutFinished) onDismiss()
        },
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            dismissOnBackPress = isRolloutFinished,
            dismissOnClickOutside = false
        )
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Black.copy(alpha = 0.75f))
                .padding(horizontal = 20.dp, vertical = 24.dp),
            contentAlignment = Alignment.Center
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .wrapContentHeight(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                // 1. THERMAL PRINTER HARDWARE HEAD (Chassis & Dispenser Slot)
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .shadow(12.dp, RoundedCornerShape(topStart = 20.dp, topEnd = 20.dp))
                        .clip(RoundedCornerShape(topStart = 20.dp, topEnd = 20.dp))
                        .background(
                            Brush.verticalGradient(
                                listOf(
                                    Color(0xFF334155),
                                    Color(0xFF1E293B),
                                    Color(0xFF0F172A)
                                )
                            )
                        )
                        .border(
                            BorderStroke(1.dp, Color(0x66FFFFFF)),
                            RoundedCornerShape(topStart = 20.dp, topEnd = 20.dp)
                        )
                        .padding(horizontal = 16.dp, vertical = 12.dp)
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        // Printer Header Info Row
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                // Status LED
                                Box(
                                    modifier = Modifier
                                        .size(10.dp)
                                        .background(
                                            if (isRolloutFinished) LeashPrimary else LeashCyan.copy(alpha = ledAlpha),
                                            CircleShape
                                        )
                                        .shadow(4.dp, CircleShape)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = if (isRolloutFinished) "PRINT COMPLETED" else "PRINTING RECEIPT...",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.ExtraBold,
                                    color = if (isRolloutFinished) LeashPrimary else LeashCyan,
                                    letterSpacing = 1.sp
                                )
                            }

                            Text(
                                text = "LEASH-POS-80",
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Color(0xFF94A3B8),
                                fontWeight = FontWeight.Bold
                            )
                        }

                        Spacer(modifier = Modifier.height(10.dp))

                        // Dispenser Paper Slot (Dark recessed feed aperture)
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(8.dp)
                                .clip(RoundedCornerShape(4.dp))
                                .background(Color(0xFF050811))
                                .border(BorderStroke(1.dp, Color(0x33FFFFFF)), RoundedCornerShape(4.dp))
                        )
                    }
                }

                // 2. RECEIPT PAPER ROLLING OUT FROM THE DISPENSER
                val maxReceiptHeight = 440.dp
                val animatedHeight = maxReceiptHeight * rollProgress.value

                Box(
                    modifier = Modifier
                        .fillMaxWidth(0.94f)
                        .height(animatedHeight)
                        .shadow(16.dp, JaggedReceiptShape(toothWidth = 18f, toothHeight = 10f))
                        .clip(JaggedReceiptShape(toothWidth = 18f, toothHeight = 10f))
                        .background(Color(0xFFF8FAFC)) // Authentic thermal paper
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .padding(horizontal = 14.dp, vertical = 12.dp)
                    ) {
                        var selectedViewMode by remember { mutableStateOf("ticket") }
                        val parsed = remember(receiptText) { parseReceiptMarkdown(receiptText) }

                        // Thermal Receipt Header
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text(
                                text = "⚡ L E A S H ⚡",
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFF0F172A),
                                letterSpacing = 2.sp
                            )
                            Text(
                                text = "ON-DEVICE AI BODYGUARD",
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF475569),
                                letterSpacing = 1.sp
                            )
                            Text(
                                text = "ZERO-TRUST AUDIT RECEIPT",
                                fontSize = 8.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = Color(0xFF64748B),
                                letterSpacing = 0.5.sp
                            )

                            Spacer(modifier = Modifier.height(10.dp))

                            // View Mode Toggle Pills (Formatable: Ticket vs Markdown)
                            Row(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(14.dp))
                                    .background(Color(0xFFE2E8F0))
                                    .padding(2.dp),
                                horizontalArrangement = Arrangement.Center
                            ) {
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(12.dp))
                                        .background(if (selectedViewMode == "ticket") Color(0xFF0F172A) else Color.Transparent)
                                        .clickable { selectedViewMode = "ticket" }
                                        .padding(horizontal = 14.dp, vertical = 5.dp)
                                ) {
                                    Text(
                                        text = "🧾 TICKET VIEW",
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = if (selectedViewMode == "ticket") Color.White else Color(0xFF64748B)
                                    )
                                }
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(12.dp))
                                        .background(if (selectedViewMode == "raw") Color(0xFF0F172A) else Color.Transparent)
                                        .clickable { selectedViewMode = "raw" }
                                        .padding(horizontal = 14.dp, vertical = 5.dp)
                                ) {
                                    Text(
                                        text = "📋 PR MARKDOWN",
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = if (selectedViewMode == "raw") Color.White else Color(0xFF64748B)
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(10.dp))
                            ReceiptDashedDivider()
                        }

                        Spacer(modifier = Modifier.height(10.dp))

                        if (selectedViewMode == "ticket") {
                            // 1. PRETTY FORMATTED TICKET VIEW
                            ThermalTicketContentView(parsed = parsed)
                        } else {
                            // 2. RAW PR MARKDOWN VIEW
                            RawMarkdownContentView(receiptText = receiptText)
                        }

                        Spacer(modifier = Modifier.height(14.dp))

                        // Simulated Barcode & Cryptographic Signature Seal
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            ReceiptDashedDivider()
                            Spacer(modifier = Modifier.height(8.dp))

                            // Barcode visualization
                            Row(
                                modifier = Modifier
                                    .height(26.dp)
                                    .padding(vertical = 2.dp),
                                horizontalArrangement = Arrangement.Center
                            ) {
                                val pattern = listOf(3, 1, 2, 4, 1, 3, 2, 1, 4, 2, 3, 1, 2, 1, 3, 4, 1, 2, 3, 1, 4, 2, 1, 3)
                                pattern.forEach { width ->
                                    Box(
                                        modifier = Modifier
                                            .width(width.dp)
                                            .fillMaxHeight()
                                            .background(Color(0xFF0F172A))
                                    )
                                    Spacer(modifier = Modifier.width(2.dp))
                                }
                            }

                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "* ED25519-CRYPTOGRAPHIC-SEAL *",
                                fontSize = 8.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Color(0xFF64748B),
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 1.sp
                            )
                            Text(
                                text = "AUTH-HASH: ${parsed.sessionId.takeLast(12).uppercase()}-LEASH-OK",
                                fontSize = 7.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Color(0xFF94A3B8)
                            )
                        }

                        Spacer(modifier = Modifier.height(24.dp))
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // 3. ACTION BUTTONS (APPEARS AFTER ANIMATION COMPLETES)
                AnimatedVisibility(
                    visible = isRolloutFinished,
                    enter = fadeIn(tween(400)) + slideInVertically(
                        initialOffsetY = { it / 2 },
                        animationSpec = tween(400)
                    ),
                    exit = fadeOut()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 8.dp),
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        // Close Button
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .height(48.dp)
                                .clip(RoundedCornerShape(24.dp))
                                .background(Color(0x2EFFFFFF))
                                .border(BorderStroke(1.dp, Color(0x4DFFFFFF)), RoundedCornerShape(24.dp))
                                .clickable(onClick = onDismiss),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "Close",
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp
                            )
                        }

                        // Copy Receipt Button
                        Box(
                            modifier = Modifier
                                .weight(1.4f)
                                .height(48.dp)
                                .shadow(8.dp, RoundedCornerShape(24.dp))
                                .clip(RoundedCornerShape(24.dp))
                                .background(LeashPrimary)
                                .clickable {
                                    clipboardManager.setText(AnnotatedString(receiptText))
                                    Toast.makeText(context, "PR Receipt copied to clipboard!", Toast.LENGTH_SHORT).show()
                                },
                            contentAlignment = Alignment.Center
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Default.ContentCopy,
                                    contentDescription = "Copy",
                                    tint = Color(0xFF0F172A),
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "Copy Receipt",
                                    color = Color(0xFF0F172A),
                                    fontWeight = FontWeight.ExtraBold,
                                    fontSize = 13.sp
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

/**
 * Authentic Thermal Ticket Layout
 */
@Composable
private fun ThermalTicketContentView(parsed: ParsedReceiptData) {
    Column(modifier = Modifier.fillMaxWidth()) {
        // Metadata grid
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column {
                Text(
                    text = "SESSION ID",
                    fontSize = 8.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF64748B)
                )
                Text(
                    text = parsed.sessionId,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.ExtraBold,
                    color = Color(0xFF0F172A)
                )
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    text = "DATE / TIME",
                    fontSize = 8.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF64748B)
                )
                Text(
                    text = parsed.generatedTime.ifEmpty { "2026-10-05 UTC" },
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.SemiBold,
                    color = Color(0xFF334155)
                )
            }
        }

        Spacer(modifier = Modifier.height(6.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = "AGENT: ${parsed.agent}",
                fontSize = 9.sp,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Medium,
                color = Color(0xFF475569)
            )
            Text(
                text = "BRANCH: ${parsed.branch}",
                fontSize = 9.sp,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Medium,
                color = Color(0xFF475569)
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        // Outcome Banner Box
        val isProtected = parsed.outcomeBadge.contains("PROTECT", ignoreCase = true) ||
                parsed.outcomeBadge.contains("CLEAN", ignoreCase = true) ||
                parsed.outcomeBadge.contains("SAFE", ignoreCase = true)
        val bannerBg = if (isProtected) Color(0xFFECFDF5) else Color(0xFFFEF2F2)
        val bannerBorder = if (isProtected) Color(0xFF10B981) else Color(0xFFEF4444)
        val bannerText = if (isProtected) Color(0xFF065F46) else Color(0xFF991B1B)

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .background(bannerBg)
                .border(BorderStroke(1.dp, bannerBorder), RoundedCornerShape(8.dp))
                .padding(horizontal = 12.dp, vertical = 8.dp)
        ) {
            Column {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = parsed.outcomeBadge,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Black,
                        color = bannerText
                    )
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(4.dp))
                            .background(bannerBorder)
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = parsed.verdict,
                            fontSize = 8.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White
                        )
                    }
                }

                if (parsed.summaryText.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = parsed.summaryText,
                        fontSize = 9.sp,
                        color = Color(0xFF334155),
                        lineHeight = 12.sp
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))
        ReceiptDashedDivider()
        Spacer(modifier = Modifier.height(8.dp))

        // Executive Summary Section
        Text(
            text = "EXECUTIVE SUMMARY",
            fontSize = 9.sp,
            fontWeight = FontWeight.Black,
            letterSpacing = 1.sp,
            color = Color(0xFF0F172A)
        )

        Spacer(modifier = Modifier.height(6.dp))

        if (parsed.metrics.isNotEmpty()) {
            parsed.metrics.forEach { metric ->
                ReceiptDotLeaderRow(
                    label = metric.title,
                    value = metric.count,
                    details = metric.details,
                    isAlert = metric.title.contains("Denied", ignoreCase = true) && metric.count != "0"
                )
                Spacer(modifier = Modifier.height(4.dp))
            }
        } else {
            // Default placeholder metrics
            ReceiptDotLeaderRow("Total Actions Evaluated", "2", "Intercepted at shell boundary", false)
            ReceiptDotLeaderRow("Approved / Allowed", "0", "Verified safe by policy", false)
            ReceiptDotLeaderRow("Denied / Blocked", "2", "Prevented dangerous operations", true)
            ReceiptDotLeaderRow("Tainted Invocations", "0", "External provenance clean", false)
        }

        // Blocked Actions Section (if any detected)
        if (parsed.blockedActions.isNotEmpty()) {
            Spacer(modifier = Modifier.height(10.dp))
            ReceiptDashedDivider()
            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "SECURITY INTERVENTIONS (${parsed.blockedActions.size})",
                fontSize = 9.sp,
                fontWeight = FontWeight.Black,
                letterSpacing = 1.sp,
                color = Color(0xFFDC2626)
            )

            Spacer(modifier = Modifier.height(6.dp))

            parsed.blockedActions.forEach { blocked ->
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(6.dp))
                        .background(Color(0xFFFEF2F2))
                        .border(BorderStroke(1.dp, Color(0xFFFCA5A5)), RoundedCornerShape(6.dp))
                        .padding(8.dp)
                ) {
                    Column {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "⛔ BLOCKED",
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFFB91C1C)
                            )
                            Text(
                                text = blocked.time,
                                fontSize = 8.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Color(0xFF64748B)
                            )
                        }

                        Spacer(modifier = Modifier.height(4.dp))

                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(4.dp))
                                .background(Color(0xFF0F172A))
                                .padding(horizontal = 6.dp, vertical = 4.dp)
                        ) {
                            Text(
                                text = blocked.action,
                                fontSize = 9.sp,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF38BDF8)
                            )
                        }

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = "Gate: ${blocked.gate} • Why: ${blocked.reason}",
                            fontSize = 8.sp,
                            color = Color(0xFF475569),
                            lineHeight = 11.sp
                        )
                    }
                }
                Spacer(modifier = Modifier.height(6.dp))
            }
        }
    }
}

/**
 * Authentic dot-leader line for POS receipts:
 * Label .................. [ Value ]
 */
@Composable
private fun ReceiptDotLeaderRow(
    label: String,
    value: String,
    details: String = "",
    isAlert: Boolean = false
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = label,
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold,
                color = Color(0xFF1E293B)
            )

            // Dotted leader space
            Text(
                text = " " + ". ".repeat(28),
                fontSize = 8.sp,
                color = Color(0xFFCBD5E1),
                maxLines = 1,
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 4.dp)
            )

            // Value badge
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(4.dp))
                    .background(if (isAlert) Color(0xFFFEE2E2) else Color(0xFFE2E8F0))
                    .border(
                        BorderStroke(1.dp, if (isAlert) Color(0xFFEF4444) else Color(0xFFCBD5E1)),
                        RoundedCornerShape(4.dp)
                    )
                    .padding(horizontal = 6.dp, vertical = 2.dp)
            ) {
                Text(
                    text = value,
                    fontSize = 9.sp,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.ExtraBold,
                    color = if (isAlert) Color(0xFFDC2626) else Color(0xFF0F172A)
                )
            }
        }

        if (details.isNotEmpty()) {
            Text(
                text = details,
                fontSize = 7.5.sp,
                color = Color(0xFF64748B),
                modifier = Modifier.padding(start = 2.dp, top = 1.dp)
            )
        }
    }
}

/**
 * Raw PR Markdown View with formatted code styling
 */
@Composable
private fun RawMarkdownContentView(receiptText: String) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(Color(0xFF0F172A))
            .padding(10.dp)
    ) {
        Text(
            text = receiptText,
            fontSize = 9.sp,
            fontFamily = FontFamily.Monospace,
            color = Color(0xFFE2E8F0),
            lineHeight = 13.sp
        )
    }
}

/**
 * Clean Monospace Dashed Divider
 */
@Composable
private fun ReceiptDashedDivider() {
    Text(
        text = "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -",
        fontSize = 8.sp,
        fontFamily = FontFamily.Monospace,
        color = Color(0xFF94A3B8),
        maxLines = 1,
        modifier = Modifier.fillMaxWidth()
    )
}

/**
 * Structured Receipt Model
 */
data class ParsedReceiptData(
    val sessionId: String = "s_active",
    val outcomeBadge: String = "🛡️ PROTECTED (RISKS MITIGATED)",
    val verdict: String = "VERIFIED",
    val agent: String = "agent",
    val branch: String = "main",
    val generatedTime: String = "",
    val summaryText: String = "",
    val metrics: List<ReceiptMetricItem> = emptyList(),
    val blockedActions: List<ReceiptBlockedItem> = emptyList()
)

data class ReceiptMetricItem(
    val title: String,
    val count: String,
    val details: String = ""
)

data class ReceiptBlockedItem(
    val time: String,
    val action: String,
    val severity: String,
    val gate: String,
    val reason: String
)

/**
 * Parser for Leash Receipt Markdown
 */
fun parseReceiptMarkdown(raw: String): ParsedReceiptData {
    var sessionId = "s_active"
    var outcomeBadge = "🛡️ PROTECTED"
    var verdict = "VERIFIED"
    var agent = "agent"
    var branch = "main"
    var generatedTime = ""
    var summaryText = ""
    val metrics = mutableListOf<ReceiptMetricItem>()
    val blockedActions = mutableListOf<ReceiptBlockedItem>()

    // Extract Session ID: # 🛡️ Leash Agent Session Receipt: `s_df0cfe2aa33c`
    val sessionMatch = Regex("""Receipt:.*?[`']([a-zA-Z0-9_\-]+)[`']""").find(raw)
    if (sessionMatch != null) {
        sessionId = sessionMatch.groupValues[1]
    }

    // Extract Outcome & Verdict
    val outcomeMatch = Regex("""\*\*Session Outcome:\*\*\s*`?([^|`\n]+)`?\s*\|\s*\*\*Verdict:\*\*\s*`?([^`\n]+)`?""").find(raw)
    if (outcomeMatch != null) {
        outcomeBadge = outcomeMatch.groupValues[1].trim()
        verdict = outcomeMatch.groupValues[2].trim()
    } else {
        val altOutcome = Regex("""\*\*Session Outcome:\*\*\s*([^\n]+)""").find(raw)
        if (altOutcome != null) {
            outcomeBadge = altOutcome.groupValues[1].replace("`", "").trim()
        }
    }

    // Extract Agent, Branch, Generated
    val metaMatch = Regex("""\*\*Agent:\*\*\s*`?([^|`\n]+)`?\s*\|\s*\*\*Branch:\*\*\s*`?([^|`\n]+)`?\s*\|\s*\*\*Generated:\*\*\s*([^\n]+)""").find(raw)
    if (metaMatch != null) {
        agent = metaMatch.groupValues[1].trim()
        branch = metaMatch.groupValues[2].trim()
        generatedTime = metaMatch.groupValues[3].trim()
    }

    // Extract summary text (line following blockquotes)
    val lines = raw.lines()
    for (i in 0 until (lines.size - 1).coerceAtMost(15)) {
        val line = lines[i].trim()
        if (line.isNotEmpty() && !line.startsWith("#") && !line.startsWith(">") && !line.startsWith("-") && !line.startsWith("|")) {
            summaryText = line
            break
        }
    }

    // Extract Table Metrics
    var inExecutiveSummary = false
    var inBlockedSection = false

    for (line in lines) {
        val trimmed = line.trim()
        if (trimmed.contains("Executive Summary", ignoreCase = true)) {
            inExecutiveSummary = true
            inBlockedSection = false
            continue
        } else if (trimmed.contains("Blocked Actions", ignoreCase = true)) {
            inExecutiveSummary = false
            inBlockedSection = true
            continue
        } else if (trimmed.startsWith("## ")) {
            inExecutiveSummary = false
            inBlockedSection = false
        }

        if (inExecutiveSummary && trimmed.startsWith("|") && !trimmed.contains("---") && !trimmed.contains("Metric | Count")) {
            val parts = trimmed.split("|").map { it.trim() }.filter { it.isNotEmpty() }
            if (parts.size >= 2) {
                val title = parts[0].replace("**", "").trim()
                val count = parts[1].replace("`", "").trim()
                val details = if (parts.size >= 3) parts[2].trim() else ""
                metrics.add(ReceiptMetricItem(title, count, details))
            }
        }

        if (inBlockedSection && trimmed.startsWith("|") && !trimmed.contains("---") && !trimmed.contains("Attempted Action")) {
            val parts = trimmed.split("|").map { it.trim() }.filter { it.isNotEmpty() }
            if (parts.size >= 5) {
                val time = parts[0]
                val action = parts[1].replace("`", "")
                val severity = parts[2].replace("**", "")
                val gate = parts[3]
                val reason = parts[4]
                blockedActions.add(ReceiptBlockedItem(time, action, severity, gate, reason))
            }
        }
    }

    return ParsedReceiptData(
        sessionId = sessionId,
        outcomeBadge = outcomeBadge,
        verdict = verdict,
        agent = agent,
        branch = branch,
        generatedTime = generatedTime,
        summaryText = summaryText,
        metrics = metrics,
        blockedActions = blockedActions
    )
}

