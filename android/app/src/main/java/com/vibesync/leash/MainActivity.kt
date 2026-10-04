package com.vibesync.leash

import android.os.Bundle
import android.os.VibrationEffect
import android.os.Vibrator
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.vibesync.leash.data.model.*
import com.vibesync.leash.network.LeashWebSocketClient
import com.vibesync.leash.service.LeashForegroundService
import com.vibesync.leash.ui.screens.ApprovalCard
import com.vibesync.leash.ui.theme.LeashTheme
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private lateinit var client: LeashWebSocketClient
    private lateinit var vibrator: Vibrator

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        vibrator = getSystemService(Vibrator::class.java)

        // Initialize connection to local laptop daemon (or 10.0.2.2 for emulator)
        client = LeashWebSocketClient(
            host = "10.0.2.2",
            port = 8765,
            sharedSecret = "leash-dev-secret-change-me"
        )
        client.connect()
        LeashForegroundService.startService(this)

        setContent {
            LeashTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    var currentAction by remember { mutableStateOf<ActionBundle?>(null) }
                    var lastProvenance by remember { mutableStateOf<ProvenanceEvent?>(null) }
                    val connectionState by client.connectionState.collectAsState()
                    val scope = rememberCoroutineScope()

                    LaunchedEffect(Unit) {
                        launch {
                            client.incomingActions.collectLatest { bundle ->
                                currentAction = bundle
                                triggerHapticAlert(bundle.assessment.severity)
                            }
                        }
                        launch {
                            client.incomingProvenance.collectLatest { pEvent ->
                                lastProvenance = pEvent
                                Toast.makeText(
                                    this@MainActivity,
                                    "Provenance Warning: ${pEvent.kind.name} (${pEvent.source})",
                                    Toast.LENGTH_LONG
                                ).show()
                            }
                        }
                    }

                    Column(modifier = Modifier.fillMaxSize()) {
                        // Connection Status Bar
                        ConnectionStatusBar(connectionState = connectionState)

                        // Provenance Taint Banner if active
                        lastProvenance?.let { pEvent ->
                            Surface(
                                color = MaterialTheme.colorScheme.errorContainer,
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 16.dp, vertical = 4.dp)
                            ) {
                                Row(
                                    modifier = Modifier.padding(12.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = "[TAINT] ${pEvent.kind.name}: ${pEvent.source}",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onErrorContainer
                                    )
                                }
                            }
                        }

                        // Main Content
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .fillMaxWidth(),
                            contentAlignment = Alignment.Center
                        ) {
                            currentAction?.let { bundle ->
                                ApprovalCard(
                                    bundle = bundle,
                                    onApprove = {
                                        if (bundle.assessment.severity == Severity.HIGH) {
                                            authenticateBiometric(bundle)
                                        } else {
                                            client.sendDecision(
                                                actionId = bundle.request.id,
                                                sessionId = bundle.request.session,
                                                verdict = Verdict.ALLOW,
                                                by = DecidedBy.TAP
                                            )
                                            currentAction = null
                                        }
                                    },
                                    onDeny = {
                                        client.sendDecision(
                                            actionId = bundle.request.id,
                                            sessionId = bundle.request.session,
                                            verdict = Verdict.DENY,
                                            by = DecidedBy.TAP,
                                            note = "Denied by user"
                                        )
                                        currentAction = null
                                    }
                                )
                            } ?: Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Text(
                                    "Leash Guard: Idle & Monitoring",
                                    style = MaterialTheme.typography.titleMedium
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    if (connectionState == ConnectionState.CONNECTED)
                                        "Secure link verified. Waiting for agent actions..."
                                    else
                                        "Secure link inactive. Fail-Closed mode enforced.",
                                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    @Composable
    private fun ConnectionStatusBar(connectionState: ConnectionState) {
        val (bgColor, textColor, label) = when (connectionState) {
            ConnectionState.CONNECTED -> Triple(Color(0xFF1B5E20), Color(0xFFC8E6C9), "SECURE WEBSOCKET: CONNECTED")
            ConnectionState.AUTHENTICATING -> Triple(Color(0xFFE65100), Color(0xFFFFE0B2), "AUTHENTICATING SHARED SECRET...")
            ConnectionState.CONNECTING -> Triple(Color(0xFF0D47A1), Color(0xFFBBDEFB), "CONNECTING TO LAPTOP...")
            ConnectionState.RECONNECTING -> Triple(Color(0xFFB71C1C), Color(0xFFFFCDD2), "RECONNECTING (FAIL-CLOSED)...")
            ConnectionState.DISCONNECTED -> Triple(Color(0xFF212121), Color(0xFFBDBDBD), "DISCONNECTED (FAIL-CLOSED)")
        }

        Surface(
            color = bgColor,
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .background(textColor, CircleShape)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = label,
                        color = textColor,
                        style = MaterialTheme.typography.labelSmall
                    )
                }
                Text(
                    text = "v1.0 HMAC",
                    color = textColor.copy(alpha = 0.7f),
                    style = MaterialTheme.typography.labelSmall
                )
            }
        }
    }

    private fun triggerHapticAlert(severity: Severity) {
        if (severity == Severity.HIGH || severity == Severity.CRITICAL) {
            val timings = longArrayOf(0, 200, 100, 400)
            vibrator.vibrate(VibrationEffect.createWaveform(timings, -1))
        } else if (severity == Severity.MEDIUM) {
            vibrator.vibrate(VibrationEffect.createOneShot(150, VibrationEffect.DEFAULT_AMPLITUDE))
        }
    }

    private fun authenticateBiometric(bundle: ActionBundle) {
        val executor = ContextCompat.getMainExecutor(this)
        val prompt = BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                client.sendDecision(
                    actionId = bundle.request.id,
                    sessionId = bundle.request.session,
                    verdict = Verdict.ALLOW,
                    by = DecidedBy.BIOMETRIC
                )
                Toast.makeText(this@MainActivity, "Approved via Biometric", Toast.LENGTH_SHORT).show()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                Toast.makeText(this@MainActivity, "Auth Failed: $errString", Toast.LENGTH_SHORT).show()
            }
        })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Confirm High-Risk Action")
            .setSubtitle(bundle.assessment.summary)
            .setNegativeButtonText("Cancel")
            .build()

        prompt.authenticate(promptInfo)
    }

    override fun onDestroy() {
        super.onDestroy()
        client.disconnect()
    }
}
