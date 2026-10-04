package com.vibesync.leash

import android.os.Bundle
import android.os.VibrationEffect
import android.os.Vibrator
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.biometric.BiometricPrompt
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.vibesync.leash.data.model.*
import com.vibesync.leash.network.LeashWebSocketClient
import com.vibesync.leash.service.LeashForegroundService
import com.vibesync.leash.ui.screens.*
import com.vibesync.leash.ui.theme.*
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private lateinit var client: LeashWebSocketClient
    private lateinit var vibrator: Vibrator

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        vibrator = getSystemService(Vibrator::class.java)

        // Initialize connection to local laptop daemon (10.0.2.2 for emulator default)
        client = LeashWebSocketClient(
            host = "10.0.2.2",
            port = 8765,
            sharedSecret = "leash-dev-secret-change-me"
        )
        client.connect()
        LeashForegroundService.startService(this)

        setContent {
            LeashTheme {
                var selectedTab by remember { mutableStateOf(GuardTab.GUARD) }
                var showDemoSheet by remember { mutableStateOf(false) }

                val connectionState by client.connectionState.collectAsState()
                val pendingQueue by client.pendingActionsQueue.collectAsState()
                val feedItems by client.actionHistory.collectAsState()
                val sessionContext by client.sessionContext.collectAsState()
                val guardStats by client.guardStats.collectAsState()

                // Haptic feedback listener
                LaunchedEffect(Unit) {
                    client.incomingActions.collectLatest { bundle ->
                        triggerHapticAlert(bundle.assessment.severity)
                    }
                }

                LaunchedEffect(Unit) {
                    client.incomingProvenance.collectLatest { pEvent ->
                        triggerHapticAlert(Severity.HIGH)
                        Toast.makeText(
                            this@MainActivity,
                            "PROVENANCE ALERT: Untrusted read in ${pEvent.source}",
                            Toast.LENGTH_LONG
                        ).show()
                    }
                }

                Scaffold(
                    topBar = {
                        LeashTopAppBar(
                            connectionState = connectionState,
                            onOpenDemoSheet = { showDemoSheet = true }
                        )
                    },
                    bottomBar = {
                        LeashBottomNav(
                            selectedTab = selectedTab,
                            pendingCount = pendingQueue.size,
                            onTabSelected = { selectedTab = it }
                        )
                    },
                    containerColor = LeashDarkBackground
                ) { paddingValues ->
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(paddingValues)
                    ) {
                        when (selectedTab) {
                            GuardTab.GUARD -> {
                                GuardMainScreen(
                                    pendingQueue = pendingQueue,
                                    connectionState = connectionState,
                                    sessionContext = sessionContext,
                                    onApprove = { bundle ->
                                        if (bundle.assessment.severity == Severity.HIGH || bundle.assessment.severity == Severity.CRITICAL) {
                                            authenticateBiometric(bundle)
                                        } else {
                                            client.approveAction(bundle, DecidedBy.TAP)
                                            Toast.makeText(this@MainActivity, "Approved (Tap)", Toast.LENGTH_SHORT).show()
                                        }
                                    },
                                    onDeny = { bundle, note ->
                                        client.denyAction(bundle, DecidedBy.TAP, note)
                                        Toast.makeText(this@MainActivity, "Action Blocked", Toast.LENGTH_SHORT).show()
                                    },
                                    onOpenDemo = { showDemoSheet = true }
                                )
                            }
                            GuardTab.FEED -> {
                                ActionFeedScreen(feedItems = feedItems)
                            }
                            GuardTab.SESSION -> {
                                SessionInfoScreen(
                                    sessionContext = sessionContext,
                                    guardStats = guardStats,
                                    onRewind = { callback ->
                                        client.triggerRewind(callback)
                                    }
                                )
                            }
                            GuardTab.PAIRING -> {
                                PairingScreen(
                                    currentHost = client.host,
                                    currentPort = client.port,
                                    currentSecret = client.sharedSecret,
                                    connectionState = connectionState,
                                    onSavePairing = { host, port, secret ->
                                        client.updatePairing(host, port, secret)
                                    },
                                    onDisconnect = {
                                        client.disconnect()
                                    }
                                )
                            }
                        }

                        if (showDemoSheet) {
                            DemoSandboxSheet(
                                onTriggerScenario = { scenario ->
                                    client.injectDemoScenario(scenario)
                                    selectedTab = GuardTab.GUARD
                                },
                                onDismiss = { showDemoSheet = false }
                            )
                        }
                    }
                }
            }
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun LeashTopAppBar(
        connectionState: ConnectionState,
        onOpenDemoSheet: () -> Unit
    ) {
        val (statusColor, statusLabel) = when (connectionState) {
            ConnectionState.CONNECTED -> Pair(LeashPrimary, "CONNECTED")
            ConnectionState.AUTHENTICATING -> Pair(LeashCyan, "AUTH")
            ConnectionState.CONNECTING -> Pair(LeashWarning, "CONNECTING")
            ConnectionState.RECONNECTING -> Pair(LeashCritical, "RETRY (FAIL-CLOSED)")
            ConnectionState.DISCONNECTED -> Pair(LeashTextMuted, "DISCONNECTED")
        }

        TopAppBar(
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "LEASH",
                        fontWeight = FontWeight.Black,
                        color = Color.White,
                        fontSize = 18.sp,
                        letterSpacing = 1.sp
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "GUARD",
                        fontWeight = FontWeight.Bold,
                        color = LeashCyan,
                        fontSize = 18.sp,
                        letterSpacing = 1.sp
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Surface(
                        color = statusColor.copy(alpha = 0.2f),
                        shape = RoundedCornerShape(8.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, statusColor.copy(alpha = 0.6f))
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(7.dp)
                                    .background(statusColor, CircleShape)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = statusLabel,
                                color = statusColor,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.ExtraBold,
                                letterSpacing = 0.5.sp
                            )
                        }
                    }
                }
            },
            actions = {
                IconButton(onClick = onOpenDemoSheet) {
                    Icon(
                        imageVector = Icons.Default.Science,
                        contentDescription = "Demo Sandbox",
                        tint = LeashCyan
                    )
                }
            },
            colors = TopAppBarDefaults.topAppBarColors(
                containerColor = LeashSurface
            )
        )
    }

    @Composable
    private fun LeashBottomNav(
        selectedTab: GuardTab,
        pendingCount: Int,
        onTabSelected: (GuardTab) -> Unit
    ) {
        NavigationBar(
            containerColor = LeashSurface,
            tonalElevation = 8.dp
        ) {
            NavigationBarItem(
                selected = selectedTab == GuardTab.GUARD,
                onClick = { onTabSelected(GuardTab.GUARD) },
                icon = {
                    BadgedBox(badge = {
                        if (pendingCount > 0) {
                            Badge(containerColor = LeashCritical) {
                                Text(pendingCount.toString(), color = Color.White, fontWeight = FontWeight.Bold)
                            }
                        }
                    }) {
                        Icon(Icons.Default.Shield, contentDescription = "Guard")
                    }
                },
                label = { Text("Guard", fontSize = 11.sp) },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = LeashPrimary,
                    selectedTextColor = LeashPrimary,
                    indicatorColor = LeashSurfaceVariant,
                    unselectedIconColor = LeashTextSecondary,
                    unselectedTextColor = LeashTextSecondary
                )
            )

            NavigationBarItem(
                selected = selectedTab == GuardTab.FEED,
                onClick = { onTabSelected(GuardTab.FEED) },
                icon = { Icon(Icons.Default.ListAlt, contentDescription = "Live Feed") },
                label = { Text("Audit Feed", fontSize = 11.sp) },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = LeashCyan,
                    selectedTextColor = LeashCyan,
                    indicatorColor = LeashSurfaceVariant,
                    unselectedIconColor = LeashTextSecondary,
                    unselectedTextColor = LeashTextSecondary
                )
            )

            NavigationBarItem(
                selected = selectedTab == GuardTab.SESSION,
                onClick = { onTabSelected(GuardTab.SESSION) },
                icon = { Icon(Icons.Default.Memory, contentDescription = "Session") },
                label = { Text("Session", fontSize = 11.sp) },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = LeashPurple,
                    selectedTextColor = LeashPurple,
                    indicatorColor = LeashSurfaceVariant,
                    unselectedIconColor = LeashTextSecondary,
                    unselectedTextColor = LeashTextSecondary
                )
            )

            NavigationBarItem(
                selected = selectedTab == GuardTab.PAIRING,
                onClick = { onTabSelected(GuardTab.PAIRING) },
                icon = { Icon(Icons.Default.SettingsEthernet, contentDescription = "Pairing") },
                label = { Text("Pairing", fontSize = 11.sp) },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = LeashPrimary,
                    selectedTextColor = LeashPrimary,
                    indicatorColor = LeashSurfaceVariant,
                    unselectedIconColor = LeashTextSecondary,
                    unselectedTextColor = LeashTextSecondary
                )
            )
        }
    }

    @Composable
    private fun GuardMainScreen(
        pendingQueue: List<ActionBundle>,
        connectionState: ConnectionState,
        sessionContext: SessionContext,
        onApprove: (ActionBundle) -> Unit,
        onDeny: (ActionBundle, String?) -> Unit,
        onOpenDemo: () -> Unit
    ) {
        if (pendingQueue.isNotEmpty()) {
            val topBundle = pendingQueue.first()
            ApprovalCard(
                bundle = topBundle,
                queueIndex = 1,
                queueTotal = pendingQueue.size,
                onApprove = { onApprove(topBundle) },
                onDeny = { reason -> onDeny(topBundle, reason) }
            )
        } else {
            // Idle Monitoring Shield
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(24.dp),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Surface(
                        color = LeashSurfaceVariant,
                        shape = CircleShape,
                        border = androidx.compose.foundation.BorderStroke(
                            2.dp,
                            if (connectionState == ConnectionState.CONNECTED) LeashPrimary.copy(alpha = 0.6f) else LeashCritical.copy(alpha = 0.6f)
                        ),
                        modifier = Modifier.size(110.dp)
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Icon(
                                imageVector = if (connectionState == ConnectionState.CONNECTED) Icons.Default.Security else Icons.Default.ShieldMoon,
                                contentDescription = "Shield Active",
                                tint = if (connectionState == ConnectionState.CONNECTED) LeashPrimary else LeashCritical,
                                modifier = Modifier.size(54.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(20.dp))

                    Text(
                        text = if (connectionState == ConnectionState.CONNECTED) "GUARD ACTIVE & MONITORING" else "FAIL-CLOSED ACTIVE",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.ExtraBold,
                        color = Color.White,
                        letterSpacing = 1.sp
                    )

                    Spacer(modifier = Modifier.height(6.dp))

                    Text(
                        text = if (connectionState == ConnectionState.CONNECTED)
                            "Interception link verified. Waiting for agent shell commands or tool actions..."
                        else
                            "Disconnected from laptop. Any agent actions are automatically blocked.",
                        style = MaterialTheme.typography.bodySmall,
                        color = LeashTextSecondary,
                        modifier = Modifier.padding(horizontal = 32.dp),
                        textAlign = androidx.compose.ui.text.style.TextAlign.Center
                    )

                    if (sessionContext.tainted) {
                        Spacer(modifier = Modifier.height(14.dp))
                        Surface(
                            color = LeashCritical.copy(alpha = 0.15f),
                            shape = RoundedCornerShape(8.dp),
                            border = androidx.compose.foundation.BorderStroke(1.dp, LeashCritical.copy(alpha = 0.5f))
                        ) {
                            Text(
                                text = "⚠ Session Tainted: Source ${sessionContext.taintSource ?: "README.md"}",
                                color = LeashCritical,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(28.dp))

                    // Demo sandbox trigger button
                    OutlinedButton(
                        onClick = onOpenDemo,
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = LeashCyan),
                        border = androidx.compose.foundation.BorderStroke(1.dp, LeashCyan.copy(alpha = 0.6f)),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Icon(Icons.Default.PlayCircle, contentDescription = "Test", modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Trigger Demo Scenario", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }

    private fun triggerHapticAlert(severity: Severity) {
        try {
            if (severity == Severity.HIGH || severity == Severity.CRITICAL) {
                val timings = longArrayOf(0, 200, 100, 300, 100, 400)
                vibrator.vibrate(VibrationEffect.createWaveform(timings, -1))
            } else if (severity == Severity.MEDIUM) {
                val timings = longArrayOf(0, 120, 80, 120)
                vibrator.vibrate(VibrationEffect.createWaveform(timings, -1))
            }
        } catch (e: Exception) {
            // Devices without vibrator service support ignore
        }
    }

    private fun authenticateBiometric(bundle: ActionBundle) {
        val executor = ContextCompat.getMainExecutor(this)
        val prompt = BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                client.approveAction(bundle, DecidedBy.BIOMETRIC)
                Toast.makeText(this@MainActivity, "Approved via Biometric Fingerprint", Toast.LENGTH_SHORT).show()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                // If biometric fails or hardware unavailable on emulator, provide fast fallback
                Toast.makeText(this@MainActivity, "Biometric Auth: $errString", Toast.LENGTH_SHORT).show()
            }

            override fun onAuthenticationFailed() {
                Toast.makeText(this@MainActivity, "Fingerprint not recognized", Toast.LENGTH_SHORT).show()
            }
        })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Confirm High-Risk Action")
            .setSubtitle(bundle.assessment.summary)
            .setDescription("Fingerprint verification required for ${bundle.assessment.severity.name} severity")
            .setNegativeButtonText("Cancel")
            .build()

        try {
            prompt.authenticate(promptInfo)
        } catch (e: Exception) {
            // Fallback to tap if biometric hardware unavailable on emulator
            client.approveAction(bundle, DecidedBy.TAP)
            Toast.makeText(this, "Approved (Fallback Tap)", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        client.disconnect()
    }
}
