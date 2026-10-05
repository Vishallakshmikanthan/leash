package com.vibesync.leash.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vibesync.leash.ui.components.GlassCard
import com.vibesync.leash.ui.theme.*

@Composable
fun SettingsScreen(
    onSavePairing: (String, Int, String) -> Unit = { _, _, _ -> },
    onDisconnect: () -> Unit = {}
) {
    var autoAllowLowRisk by remember { mutableStateOf(true) }
    var failClosedDangerous by remember { mutableStateOf(true) }
    var biometricRequired by remember { mutableStateOf(true) }
    var hapticFeedback by remember { mutableStateOf(true) }
    var officeKitSync by remember { mutableStateOf(true) }
    var timeoutSeconds by remember { mutableFloatStateOf(30f) }

    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(GlassBackgroundGradient)
            .padding(16.dp)
            .padding(bottom = 85.dp)
            .verticalScroll(scrollState)
    ) {
        Text(
            text = "SAFETY POLICY & CONTROLS",
            fontSize = 18.sp,
            fontWeight = FontWeight.Black,
            color = Color.White,
            letterSpacing = 1.sp
        )
        Text(
            text = "Configure local policy enforcement authority and on-device security rules.",
            fontSize = 12.sp,
            color = Color(0xFF94A3B8)
        )

        Spacer(modifier = Modifier.height(16.dp))

        // Policy Settings Card
        GlassCard(
            modifier = Modifier.fillMaxWidth(),
            cornerRadius = 20.dp,
            backgroundColor = Color(0x331E293B),
            borderBrush = GlassCardBorderSubtle
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "ENFORCEMENT RULES",
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    color = LeashCyan,
                    letterSpacing = 0.5.sp
                )
                Spacer(modifier = Modifier.height(12.dp))

                // Auto Allow Low Risk
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Auto-Allow Safe Commands", fontWeight = FontWeight.SemiBold, color = Color.White, fontSize = 14.sp)
                        Text("Silent execution for pytest, linters, git status without prompt fatigue.", color = LeashTextSecondary, fontSize = 11.sp)
                    }
                    Switch(
                        checked = autoAllowLowRisk,
                        onCheckedChange = { autoAllowLowRisk = it },
                        colors = SwitchDefaults.colors(checkedThumbColor = LeashPrimary, checkedTrackColor = LeashPrimary.copy(alpha = 0.4f))
                    )
                }

                Divider(color = LeashBorder, modifier = Modifier.padding(vertical = 12.dp))

                // Fail Closed
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Fail-Closed on Unreachable", fontWeight = FontWeight.SemiBold, color = Color.White, fontSize = 14.sp)
                        Text("Denies dangerous actions automatically if phone link is disconnected.", color = LeashTextSecondary, fontSize = 11.sp)
                    }
                    Switch(
                        checked = failClosedDangerous,
                        onCheckedChange = { failClosedDangerous = it },
                        colors = SwitchDefaults.colors(checkedThumbColor = LeashCritical, checkedTrackColor = LeashCritical.copy(alpha = 0.4f))
                    )
                }

                Divider(color = LeashBorder, modifier = Modifier.padding(vertical = 12.dp))

                // Biometrics Required
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Biometric Approval for High Risk", fontWeight = FontWeight.SemiBold, color = Color.White, fontSize = 14.sp)
                        Text("Fingerprint scan required for remote script execution & destructive actions.", color = LeashTextSecondary, fontSize = 11.sp)
                    }
                    Switch(
                        checked = biometricRequired,
                        onCheckedChange = { biometricRequired = it },
                        colors = SwitchDefaults.colors(checkedThumbColor = LeashCyan, checkedTrackColor = LeashCyan.copy(alpha = 0.4f))
                    )
                }

                Divider(color = LeashBorder, modifier = Modifier.padding(vertical = 12.dp))

                // Timeout Slider
                Column(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text("Decision Timeout", fontWeight = FontWeight.SemiBold, color = Color.White, fontSize = 14.sp)
                        Text("${timeoutSeconds.toInt()}s (Default: 30s)", fontWeight = FontWeight.Bold, color = LeashCyan, fontSize = 13.sp)
                    }
                    Text("Time allowed to approve before action is denied closed.", color = LeashTextSecondary, fontSize = 11.sp)
                    Slider(
                        value = timeoutSeconds,
                        onValueChange = { timeoutSeconds = it },
                        valueRange = 10f..120f,
                        steps = 10,
                        colors = SliderDefaults.colors(thumbColor = LeashCyan, activeTrackColor = LeashCyan)
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Device & Office Kit Card
        Card(
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = LeashSurface),
            border = androidx.compose.foundation.BorderStroke(1.dp, LeashBorder),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "DEVICE & OFFICE KIT INTEGRATION",
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    color = LeashPurple,
                    letterSpacing = 0.5.sp
                )
                Spacer(modifier = Modifier.height(12.dp))

                // Haptics
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Vibration Waveforms", fontWeight = FontWeight.SemiBold, color = Color.White, fontSize = 14.sp)
                        Text("Distinct haptic patterns for Medium vs High risk actions.", color = LeashTextSecondary, fontSize = 11.sp)
                    }
                    Switch(
                        checked = hapticFeedback,
                        onCheckedChange = { hapticFeedback = it },
                        colors = SwitchDefaults.colors(checkedThumbColor = LeashPurple, checkedTrackColor = LeashPurple.copy(alpha = 0.4f))
                    )
                }

                Divider(color = LeashBorder, modifier = Modifier.padding(vertical = 12.dp))

                // Office Kit Clipboard
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Office Kit Shared Clipboard", fontWeight = FontWeight.SemiBold, color = Color.White, fontSize = 14.sp)
                        Text("Sync PR receipts, diff patches, and clipboard decision tokens.", color = LeashTextSecondary, fontSize = 11.sp)
                    }
                    Switch(
                        checked = officeKitSync,
                        onCheckedChange = { officeKitSync = it },
                        colors = SwitchDefaults.colors(checkedThumbColor = LeashCyan, checkedTrackColor = LeashCyan.copy(alpha = 0.4f))
                    )
                }
            }
        }
    }
}
