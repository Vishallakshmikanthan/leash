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
                            .padding(horizontal = 16.dp, vertical = 14.dp)
                    ) {
                        // Receipt Header
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text(
                                text = "⚡ L E A S H ⚡",
                                fontSize = 15.sp,
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
                                text = "ZERO-TRUST VERIFIED RECEIPT",
                                fontSize = 8.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = Color(0xFF64748B)
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = "--------------------------------------------------",
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Color(0xFFCBD5E1),
                                maxLines = 1
                            )
                        }

                        Spacer(modifier = Modifier.height(6.dp))

                        // Formatted Receipt Body
                        Text(
                            text = receiptText,
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace,
                            color = Color(0xFF1E293B),
                            lineHeight = 14.sp
                        )

                        Spacer(modifier = Modifier.height(10.dp))

                        // Simulated Barcode
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text(
                                text = "--------------------------------------------------",
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Color(0xFFCBD5E1),
                                maxLines = 1
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            // Barcode visualization
                            Row(
                                modifier = Modifier
                                    .height(28.dp)
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
                            Text(
                                text = "* LEASH-AUDIT-VERIFIED *",
                                fontSize = 8.sp,
                                fontFamily = FontFamily.Monospace,
                                color = Color(0xFF64748B),
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 1.sp
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
