package com.vibesync.leash

import android.os.Bundle
import android.os.VibrationEffect
import android.os.Vibrator
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.biometric.BiometricPrompt
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
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
            sharedSecret = "leash-dev-secret-change-me",
            context = this
        )
        client.connect()
        LeashForegroundService.startService(this)

        setContent {
            LeashTheme {
                var selectedTab by remember { mutableStateOf(GuardTab.GUARD) }
                var showDemoSheet by remember { mutableStateOf(false) }

                val connectionState by client.connectionState.collectAsState()
                val pendingQueue by client.pendingActionsQueue.collectAsState()
                val blockedNotice by client.lastBlockedNotice.collectAsState()
                val feedItems by client.actionHistory.collectAsState()
                val sessionContext by client.sessionContext.collectAsState()
                val sessionActivity by client.sessionActivity.collectAsState()
                val guardStats by client.guardStats.collectAsState()

                // Haptic feedback listener for incoming actions
                LaunchedEffect(Unit) {
                    client.incomingActions.collectLatest { bundle ->
                        triggerHapticAlert(bundle.assessment.severity)
                    }
                }

                // Haptic feedback listener for provenance alerts
                LaunchedEffect(Unit) {
                    client.incomingProvenance.collectLatest { pEvent ->
                        triggerHapticAlert(Severity.HIGH)
                        Toast.makeText(
                            this@MainActivity,
                            "PROVENANCE ALERT: Untrusted input in ${pEvent.source}",
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
                                    blockedNotice = blockedNotice,
                                    connectionState = connectionState,
                                    sessionContext = sessionContext,
                                    onApprove = { bundle, decidedBy ->
                                        if (decidedBy == DecidedBy.BIOMETRIC) {
                                            authenticateBiometric(bundle)
                                        } else {
                                            client.approveAction(bundle, DecidedBy.TAP)
                                            triggerApprovedHaptic()
                                            Toast.makeText(this@MainActivity, "Approved via Tap", Toast.LENGTH_SHORT).show()
                                        }
                                    },
                                    onDeny = { bundle, note ->
                                        client.denyAction(bundle, DecidedBy.TAP, note)
                                        triggerBlockedHaptic()
                                        Toast.makeText(this@MainActivity, "Action Blocked (Feedback Sent)", Toast.LENGTH_SHORT).show()
                                    },
                                    onTimeout = { bundle ->
                                        client.timeoutAction(bundle)
                                        triggerBlockedHaptic()
                                        Toast.makeText(this@MainActivity, "Action Timed Out (Fail-Closed)", Toast.LENGTH_SHORT).show()
                                    },
                                    onDismissBlockedNotice = {
                                        client.clearBlockedNotice()
                                    },
                                    onViewFeed = {
                                        selectedTab = GuardTab.FEED
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
                                    sessionActivity = sessionActivity,
                                    feedItems = feedItems,
                                    onRefreshActivity = {
                                        client.requestSessionActivity()
                                    },
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
        blockedNotice: BlockedNotice?,
        connectionState: ConnectionState,
        sessionContext: SessionContext,
        onApprove: (ActionBundle, DecidedBy) -> Unit,
        onDeny: (ActionBundle, String?) -> Unit,
        onTimeout: (ActionBundle) -> Unit,
        onDismissBlockedNotice: () -> Unit,
        onViewFeed: () -> Unit,
        onOpenDemo: () -> Unit
    ) {
        var queueIndex by remember { mutableIntStateOf(0) }

        // Keep queueIndex clamped to pending queue bounds
        LaunchedEffect(pendingQueue.size) {
            if (pendingQueue.isEmpty()) {
                queueIndex = 0
            } else if (queueIndex >= pendingQueue.size) {
                queueIndex = pendingQueue.size - 1
            }
        }

        Column(modifier = Modifier.fillMaxSize()) {
            // Blocked-Action Feedback Banner (Failsafe confirmation)
            AnimatedVisibility(
                visible = blockedNotice != null,
                enter = slideInVertically() + fadeIn(),
                exit = slideOutVertically() + fadeOut()
            ) {
                blockedNotice?.let { notice ->
                    BlockedActionBanner(
                        notice = notice,
                        onDismiss = onDismissBlockedNotice,
                        onViewFeed = onViewFeed
                    )
                }
            }

            if (pendingQueue.isNotEmpty()) {
                val clampedIndex = queueIndex.coerceIn(0, pendingQueue.size - 1)
                val currentBundle = pendingQueue[clampedIndex]

                ApprovalCard(
                    bundle = currentBundle,
                    queueIndex = clampedIndex + 1,
                    queueTotal = pendingQueue.size,
                    initialTimeoutSeconds = 30,
                    onNextInQueue = {
                        if (queueIndex < pendingQueue.size - 1) queueIndex += 1 else queueIndex = 0
                    },
                    onPreviousInQueue = {
                        if (queueIndex > 0) queueIndex -= 1 else queueIndex = pendingQueue.size - 1
                    },
                    onApprove = { decidedBy -> onApprove(currentBundle, decidedBy) },
                    onDeny = { reason -> onDeny(currentBundle, reason) },
                    onTimeout = { onTimeout(currentBundle) }
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
                                    text = "⚠ Session Tainted: Source ${sessionContext.taintSource ?: "README.md"}${sessionContext.taintLine?.let { ":$it" } ?: ""}",
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
    }

    @Composable
    private fun BlockedActionBanner(
        notice: BlockedNotice,
        onDismiss: () -> Unit,
        onViewFeed: () -> Unit
    ) {
        Surface(
            color = Color(0xFF2D1215),
            shape = RoundedCornerShape(bottomStart = 16.dp, bottomEnd = 16.dp),
            border = androidx.compose.foundation.BorderStroke(1.5.dp, LeashCritical.copy(alpha = 0.7f)),
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 6.dp)
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Block,
                            contentDescription = "Action Blocked",
                            tint = LeashCritical,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "BLOCKED BY LEASH (FAIL-CLOSED)",
                            color = LeashCritical,
                            fontWeight = FontWeight.ExtraBold,
                            fontSize = 12.sp,
                            letterSpacing = 0.5.sp
                        )
                    }

                    IconButton(
                        onClick = onDismiss,
                        modifier = Modifier.size(24.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Close,
                            contentDescription = "Dismiss notice",
                            tint = LeashTextSecondary,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(6.dp))

                // Blocked Command preview
                Text(
                    text = notice.command,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    color = Color(0xFFFF8A80),
                    maxLines = 1
                )

                Spacer(modifier = Modifier.height(4.dp))

                Text(
                    text = "Reason: ${notice.reason} (${notice.decidedBy.name})",
                    fontSize = 11.sp,
                    color = LeashTextPrimary
                )

                Spacer(modifier = Modifier.height(2.dp))

                Text(
                    text = "Agent feedback sent: \"blocked by Leash: ${notice.reason}\"",
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = LeashTextMuted
                )

                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(
                        onClick = onViewFeed,
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)
                    ) {
                        Text("View in Audit Feed", color = LeashCyan, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }

    private fun triggerHapticAlert(severity: Severity) {
        try {
            if (vibrator.hasVibrator()) {
                if (severity == Severity.HIGH || severity == Severity.CRITICAL) {
                    // Urgent triple-pulse waveform with assertive amplitudes
                    val timings = longArrayOf(0, 180, 80, 260, 80, 380)
                    val amplitudes = intArrayOf(0, 200, 0, 240, 0, 255)
                    if (vibrator.hasAmplitudeControl()) {
                        vibrator.vibrate(VibrationEffect.createWaveform(timings, amplitudes, -1))
                    } else {
                        vibrator.vibrate(VibrationEffect.createWaveform(timings, -1))
                    }
                } else if (severity == Severity.MEDIUM) {
                    // Distinct double-pulse nudge with moderate amplitude
                    val timings = longArrayOf(0, 100, 70, 100)
                    val amplitudes = intArrayOf(0, 140, 0, 140)
                    if (vibrator.hasAmplitudeControl()) {
                        vibrator.vibrate(VibrationEffect.createWaveform(timings, amplitudes, -1))
                    } else {
                        vibrator.vibrate(VibrationEffect.createWaveform(timings, -1))
                    }
                }
            }
        } catch (e: Exception) {
            // Devices without vibrator service support ignore
        }
    }

    private fun triggerBlockedHaptic() {
        try {
            if (vibrator.hasVibrator()) {
                // Assertive denial feedback pulse
                val timings = longArrayOf(0, 250, 100, 250)
                val amplitudes = intArrayOf(0, 255, 0, 180)
                if (vibrator.hasAmplitudeControl()) {
                    vibrator.vibrate(VibrationEffect.createWaveform(timings, amplitudes, -1))
                } else {
                    vibrator.vibrate(VibrationEffect.createWaveform(timings, -1))
                }
            }
        } catch (e: Exception) {}
    }

    private fun triggerApprovedHaptic() {
        try {
            if (vibrator.hasVibrator()) {
                // Crisp confirmation click
                vibrator.vibrate(VibrationEffect.createOneShot(50, 120))
            }
        } catch (e: Exception) {}
    }

    private fun authenticateBiometric(bundle: ActionBundle) {
        val executor = ContextCompat.getMainExecutor(this)
        val prompt = BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                client.approveAction(bundle, DecidedBy.BIOMETRIC)
                triggerApprovedHaptic()
                Toast.makeText(this@MainActivity, "Approved via Biometric Fingerprint", Toast.LENGTH_SHORT).show()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                // If user clicks negative button ("Use Tap Fallback") or hardware is unavailable
                if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                    errorCode == BiometricPrompt.ERROR_HW_UNAVAILABLE ||
                    errorCode == BiometricPrompt.ERROR_HW_NOT_PRESENT ||
                    errorCode == BiometricPrompt.ERROR_NO_BIOMETRICS
                ) {
                    client.approveAction(bundle, DecidedBy.TAP)
                    triggerApprovedHaptic()
                    Toast.makeText(this@MainActivity, "Approved via Tap Fallback", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this@MainActivity, "Biometric: $errString (Tap Fallback Available)", Toast.LENGTH_SHORT).show()
                }
            }

            override fun onAuthenticationFailed() {
                Toast.makeText(this@MainActivity, "Fingerprint not recognized. Retry or use Tap Fallback.", Toast.LENGTH_SHORT).show()
            }
        })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Confirm High-Risk Action")
            .setSubtitle("${bundle.assessment.severity.name}: ${bundle.assessment.category}")
            .setDescription(bundle.assessment.summary)
            .setNegativeButtonText("Use Tap Fallback")
            .build()

        try {
            prompt.authenticate(promptInfo)
        } catch (e: Exception) {
            // Immediate tap fallback if biometric manager is not accessible (e.g. basic emulator)
            client.approveAction(bundle, DecidedBy.TAP)
            triggerApprovedHaptic()
            Toast.makeText(this, "Approved via Tap Fallback", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        client.disconnect()
    }
}
