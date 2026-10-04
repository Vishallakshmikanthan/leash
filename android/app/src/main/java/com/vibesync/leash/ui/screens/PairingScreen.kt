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
import com.vibesync.leash.data.model.ConnectionState
import com.vibesync.leash.ui.theme.*

@Composable
fun PairingScreen(
    currentHost: String,
    currentPort: Int,
    currentSecret: String,
    connectionState: ConnectionState,
    onSavePairing: (String, Int, String) -> Unit,
    onDisconnect: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var host by remember(currentHost) { mutableStateOf(currentHost) }
    var portStr by remember(currentPort) { mutableStateOf(currentPort.toString()) }
    var secret by remember(currentSecret) { mutableStateOf(currentSecret) }
    var qrUriInput by remember { mutableStateOf("") }
    var showQrInput by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(LeashDarkBackground)
            .padding(16.dp)
            .verticalScroll(rememberScrollState())
    ) {
        // Connection Status Banner
        val (statusColor, statusTitle, statusSub) = when (connectionState) {
            ConnectionState.CONNECTED -> Triple(
                LeashPrimary,
                "AUTHENTICATED & SECURE",
                "Bidirectional HMAC link active. Real-time interception ready."
            )
            ConnectionState.AUTHENTICATING -> Triple(
                LeashCyan,
                "HANDSHAKE IN PROGRESS",
                "Verifying shared secret and crypto signature with laptop..."
            )
            ConnectionState.CONNECTING -> Triple(
                LeashWarning,
                "CONNECTING TO DAEMON",
                "Initiating WebSocket connection to $currentHost:$currentPort..."
            )
            ConnectionState.RECONNECTING -> Triple(
                LeashCritical,
                "LINK SEVERED (FAIL-CLOSED)",
                "Laptop disconnected. All high-risk agent operations blocked."
            )
            ConnectionState.DISCONNECTED -> Triple(
                LeashTextMuted,
                "DISCONNECTED",
                "Guard is offline. Fail-closed policy enforces agent block."
            )
        }

        Card(
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = LeashSurface),
            border = androidx.compose.foundation.BorderStroke(1.dp, statusColor.copy(alpha = 0.6f)),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier.padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(14.dp)
                        .background(statusColor, CircleShape)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column {
                    Text(
                        text = statusTitle,
                        color = statusColor,
                        fontWeight = FontWeight.ExtraBold,
                        fontSize = 12.sp,
                        letterSpacing = 0.8.sp
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = statusSub,
                        color = LeashTextSecondary,
                        fontSize = 12.sp
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Device Pairing Form Card
        Card(
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = LeashSurface),
            border = androidx.compose.foundation.BorderStroke(1.dp, LeashBorder),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(18.dp)) {
                Text(
                    text = "LAPTOP DAEMON LINK",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = LeashCyan,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(14.dp))

                // Host
                OutlinedTextField(
                    value = host,
                    onValueChange = { host = it },
                    label = { Text("Daemon IP / Hostname") },
                    leadingIcon = { Icon(Icons.Default.Lan, contentDescription = "Host") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = LeashPrimary,
                        unfocusedBorderColor = LeashBorder,
                        focusedTextColor = LeashTextPrimary,
                        unfocusedTextColor = LeashTextPrimary
                    ),
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(10.dp))

                // Port
                OutlinedTextField(
                    value = portStr,
                    onValueChange = { portStr = it },
                    label = { Text("Port (default 8765)") },
                    leadingIcon = { Icon(Icons.Default.Numbers, contentDescription = "Port") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = LeashPrimary,
                        unfocusedBorderColor = LeashBorder,
                        focusedTextColor = LeashTextPrimary,
                        unfocusedTextColor = LeashTextPrimary
                    ),
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(10.dp))

                // Shared Secret
                OutlinedTextField(
                    value = secret,
                    onValueChange = { secret = it },
                    label = { Text("HMAC Shared Secret") },
                    leadingIcon = { Icon(Icons.Default.Key, contentDescription = "Secret") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = LeashPrimary,
                        unfocusedBorderColor = LeashBorder,
                        focusedTextColor = LeashTextPrimary,
                        unfocusedTextColor = LeashTextPrimary
                    ),
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(16.dp))

                // Quick Presets
                Text(
                    text = "QUICK PRESETS",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = LeashTextSecondary
                )
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FilledTonalButton(
                        onClick = {
                            host = "10.0.2.2"
                            portStr = "8765"
                        },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.filledTonalButtonColors(containerColor = LeashSurfaceVariant)
                    ) {
                        Text("Emulator", fontSize = 11.sp)
                    }
                    FilledTonalButton(
                        onClick = {
                            host = "127.0.0.1"
                            portStr = "8765"
                        },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.filledTonalButtonColors(containerColor = LeashSurfaceVariant)
                    ) {
                        Text("USB / ADB", fontSize = 11.sp)
                    }
                }

                Spacer(modifier = Modifier.height(20.dp))

                // Connect / Reconnect Button
                Button(
                    onClick = {
                        val parsedPort = portStr.toIntOrNull() ?: 8765
                        onSavePairing(host, parsedPort, secret)
                        Toast.makeText(context, "Connecting to $host:$parsedPort...", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = LeashPrimary,
                        contentColor = Color.Black
                    )
                ) {
                    Icon(Icons.Default.Link, contentDescription = "Connect")
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Save & Connect Link", fontWeight = FontWeight.Bold)
                }

                if (connectionState == ConnectionState.CONNECTED) {
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedButton(
                        onClick = onDisconnect,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(44.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = LeashCritical),
                        border = androidx.compose.foundation.BorderStroke(1.dp, LeashCritical)
                    ) {
                        Text("Sever Link (Test Fail-Closed)")
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Security Protocol Specs Card
        Card(
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = LeashSurface),
            border = androidx.compose.foundation.BorderStroke(1.dp, LeashBorder),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(18.dp)) {
                Text(
                    text = "CRYPTOGRAPHIC PROTOCOL SPECS",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = LeashPurple,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(10.dp))
                ProtocolSpecRow("Signature Algorithm", "HMAC-SHA256")
                ProtocolSpecRow("Replay Window", "60 seconds nonce cache")
                ProtocolSpecRow("Heartbeat Interval", "15 seconds ping / ack")
                ProtocolSpecRow("Policy Mode", "Fail-Closed (Deny on disconnect)")
                ProtocolSpecRow("In-Flight Security", "Canonical JSON serialization")
            }
        }
    }
}

@Composable
fun ProtocolSpecRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(text = label, color = LeashTextSecondary, fontSize = 12.sp)
        Text(
            text = value,
            color = LeashCyan,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Medium
        )
    }
}
