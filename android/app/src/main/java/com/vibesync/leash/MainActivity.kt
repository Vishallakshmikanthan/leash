package com.vibesync.leash

import android.os.Bundle
import android.os.VibrationEffect
import android.os.Vibrator
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
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
                    val scope = rememberCoroutineScope()

                    LaunchedEffect(Unit) {
                        client.incomingActions.collectLatest { bundle ->
                            currentAction = bundle
                            triggerHapticAlert(bundle.assessment.severity)
                        }
                    }

                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
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
                            Text("Leash Guard: Idle & Monitoring", style = MaterialTheme.typography.titleMedium)
                            Spacer(modifier = Modifier.height(8.dp))
                            Text("Waiting for agent actions...", color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
                        }
                    }
                }
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
