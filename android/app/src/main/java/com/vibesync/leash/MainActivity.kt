package com.vibesync.leash

import android.os.Bundle
import android.os.VibrationEffect
import android.os.Vibrator
import android.widget.Toast
import androidx.fragment.app.FragmentActivity
import androidx.activity.compose.setContent
import androidx.biometric.BiometricPrompt
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.BorderStroke
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.vibesync.leash.data.model.*
import com.vibesync.leash.network.LeashWebSocketClient
import com.vibesync.leash.service.LeashForegroundService
import com.vibesync.leash.ui.components.*
import com.vibesync.leash.ui.screens.*
import com.vibesync.leash.ui.theme.*
import kotlinx.coroutines.flow.collectLatest

class MainActivity : FragmentActivity() {

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

        // Wire notification approval action handler
        LeashForegroundService.onNotificationDecision = { actionId, approve ->
            val bundle = client.pendingActionsQueue.value.find { it.request.id == actionId }
            if (bundle != null) {
                if (approve) {
                    client.approveAction(bundle, DecidedBy.TAP)
                    triggerApprovedHaptic()
                    Toast.makeText(this, "Approved via notification", Toast.LENGTH_SHORT).show()
                } else {
                    client.denyAction(bundle, DecidedBy.TAP, "Blocked via lock-screen notification")
                    triggerBlockedHaptic()
                    Toast.makeText(this, "Blocked via notification", Toast.LENGTH_SHORT).show()
                }
            }
        }

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
                        LeashForegroundService.showApprovalNotification(
                            this@MainActivity,
                            bundle.request.id,
                            bundle.request.command ?: bundle.request.target_path ?: "-",
                            bundle.assessment.severity.name,
                            bundle.request.agent
                        )
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

                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(GlassBackgroundGradient)
                ) {
                    Scaffold(
                        topBar = {
                            LeashTopAppBar(
                                connectionState = connectionState,
                                onOpenDemoSheet = { showDemoSheet = true },
                                onOpenPairing = { selectedTab = GuardTab.PAIRING }
                            )
                        },
                        bottomBar = {
                            LeashBottomNav(
                                selectedTab = selectedTab,
                                pendingCount = pendingQueue.size,
                                onTabSelected = { selectedTab = it }
                            )
                        },
                        containerColor = Color.Transparent
                    ) { paddingValues ->
                        Box(
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(paddingValues)
                        ) {
                            AnimatedContent(
                                targetState = selectedTab,
                                transitionSpec = {
                                    fadeIn(animationSpec = tween(220)) togetherWith fadeOut(animationSpec = tween(220))
                                },
                                label = "tab_crossfade"
                            ) { currentTab ->
                                when (currentTab) {
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
                                            onOpenDemo = { showDemoSheet = true },
                                            onOpenPairing = { selectedTab = GuardTab.PAIRING }
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
                                    GuardTab.AUDIT -> {
                                        AuditHistoryScreen(
                                            feedItems = feedItems,
                                            onRefresh = {
                                                client.requestSessionActivity()
                                            }
                                        )
                                    }
                                    GuardTab.SETTINGS -> {
                                        SettingsScreen(
                                            onSavePairing = { host, port, secret ->
                                                client.updatePairing(host, port, secret)
                                            },
                                            onDisconnect = {
                                                client.disconnect()
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
                                            },
                                            onPairWithPin = { host, port, pin, callback ->
                                                client.pairWithPin(host, port, pin, callback)
                                            }
                                        )
                                    }
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
    }

    @Composable
    private fun LeashTopAppBar(
        connectionState: ConnectionState,
        onOpenDemoSheet: () -> Unit,
        onOpenPairing: () -> Unit
    ) {
        val (statusColor, statusLabel) = when (connectionState) {
            ConnectionState.CONNECTED -> Pair(LeashPrimary, "CONNECTED")
            ConnectionState.AUTHENTICATING -> Pair(LeashCyan, "AUTH")
            ConnectionState.CONNECTING -> Pair(LeashWarning, "CONNECTING")
            ConnectionState.RECONNECTING -> Pair(LeashCritical, "RETRY")
            ConnectionState.DISCONNECTED -> Pair(LeashTextMuted, "DISCONNECTED")
        }

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .statusBarsPadding()
                .padding(horizontal = 16.dp, vertical = 8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                // App Logo / Brand (matching ⚡ Finzo in reference image)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(32.dp)
                            .clip(RoundedCornerShape(10.dp))
                            .background(Color(0x38FFFFFF))
                            .border(BorderStroke(1.dp, Color(0x66FFFFFF)), RoundedCornerShape(10.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Bolt,
                            contentDescription = "Leash",
                            tint = Color.White,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Leash",
                        fontWeight = FontWeight.Black,
                        color = Color.White,
                        fontSize = 20.sp,
                        letterSpacing = (-0.5).sp
                    )
                }

                // Middle Status Capsule Pill
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(16.dp))
                        .background(Color(0x2EFFFFFF))
                        .border(BorderStroke(1.dp, Color(0x4DFFFFFF)), RoundedCornerShape(16.dp))
                        .padding(horizontal = 10.dp, vertical = 4.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(7.dp)
                                .background(statusColor, CircleShape)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = statusLabel,
                            color = Color.White,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.ExtraBold,
                            letterSpacing = 0.5.sp
                        )
                    }
                }

                // Right Actions: QR Scanner icon in frosted square + Demo Sandbox
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Box(
                        modifier = Modifier
                            .size(34.dp)
                            .clip(RoundedCornerShape(10.dp))
                            .background(Color(0x2EFFFFFF))
                            .border(BorderStroke(1.dp, Color(0x4DFFFFFF)), RoundedCornerShape(10.dp))
                            .clickable(onClick = onOpenPairing),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.QrCodeScanner,
                            contentDescription = "Pairing",
                            tint = Color.White,
                            modifier = Modifier.size(17.dp)
                        )
                    }

                    Box(
                        modifier = Modifier
                            .size(34.dp)
                            .clip(RoundedCornerShape(10.dp))
                            .background(Color(0x2EFFFFFF))
                            .border(BorderStroke(1.dp, Color(0x4DFFFFFF)), RoundedCornerShape(10.dp))
                            .clickable(onClick = onOpenDemoSheet),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Science,
                            contentDescription = "Demo Sandbox",
                            tint = Color.White,
                            modifier = Modifier.size(17.dp)
                        )
                    }
                }
            }
        }
    }

    @Composable
    private fun LeashBottomNav(
        selectedTab: GuardTab,
        pendingCount: Int,
        onTabSelected: (GuardTab) -> Unit
    ) {
        val currentDockIndex = when (selectedTab) {
            GuardTab.GUARD -> 0
            GuardTab.SESSION -> 1
            GuardTab.FEED, GuardTab.AUDIT -> 2
            GuardTab.SETTINGS, GuardTab.PAIRING -> 3
        }

        GlassFloatingDock(
            currentTab = currentDockIndex,
            pendingBadgeCount = pendingCount,
            onTabSelected = { idx ->
                val targetTab = when (idx) {
                    0 -> GuardTab.GUARD
                    1 -> GuardTab.SESSION
                    2 -> GuardTab.FEED
                    3 -> GuardTab.SETTINGS
                    else -> GuardTab.GUARD
                }
                onTabSelected(targetTab)
            }
        )
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
        onOpenDemo: () -> Unit,
        onOpenPairing: () -> Unit = {}
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
                // High-End Hero / Standby Screen (Matching Phone 1 in Reference Image)
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 24.dp)
                        .padding(top = 10.dp, bottom = 85.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier.fillMaxHeight()
                    ) {
                        Spacer(modifier = Modifier.height(10.dp))

                        // Hero Visual Badge (Representing Hardware Safety Token / Guard Card)
                        Box(
                            modifier = Modifier
                                .size(160.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            // Ambient Outer Frosted Glow
                            Box(
                                modifier = Modifier
                                    .size(150.dp)
                                    .clip(CircleShape)
                                    .background(Color(0x24FFFFFF))
                                    .border(BorderStroke(1.dp, Color(0x38FFFFFF)), CircleShape)
                            )
                            // Mid Ring
                            Box(
                                modifier = Modifier
                                    .size(116.dp)
                                    .clip(CircleShape)
                                    .background(Color(0x38FFFFFF))
                                    .border(BorderStroke(1.5.dp, Color(0x80FFFFFF)), CircleShape)
                            )
                            // Inner Core
                            Box(
                                modifier = Modifier
                                    .size(80.dp)
                                    .clip(RoundedCornerShape(22.dp))
                                    .background(
                                        Brush.linearGradient(
                                            listOf(
                                                Color(0xFF1E293B),
                                                Color(0xFF0F172A)
                                            )
                                        )
                                    )
                                    .border(BorderStroke(1.5.dp, Color(0x99FFFFFF)), RoundedCornerShape(22.dp)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = if (connectionState == ConnectionState.CONNECTED) Icons.Default.Shield else Icons.Default.ShieldMoon,
                                    contentDescription = "Shield Active",
                                    tint = if (connectionState == ConnectionState.CONNECTED) LeashPrimary else LeashCritical,
                                    modifier = Modifier.size(42.dp)
                                )
                            }
                        }

                        // Bold Typography matching "Clear Track of Expenses."
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally,
                            modifier = Modifier.padding(horizontal = 8.dp)
                        ) {
                            Text(
                                text = "Clear Control of\nAI Agents.",
                                fontSize = 32.sp,
                                fontWeight = FontWeight.Black,
                                color = Color.White,
                                lineHeight = 38.sp,
                                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                                letterSpacing = (-1).sp
                            )

                            Spacer(modifier = Modifier.height(10.dp))

                            Text(
                                text = if (connectionState == ConnectionState.CONNECTED)
                                    "On-device zero-trust bodyguard. All agent shell actions require verified phone clearance."
                                else
                                    "Disconnected from laptop. Any agent actions are automatically blocked (Fail-Closed).",
                                fontSize = 12.sp,
                                color = Color(0xCCFFFFFF),
                                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                                lineHeight = 17.sp,
                                modifier = Modifier.padding(horizontal = 16.dp)
                            )

                            if (sessionContext.tainted) {
                                Spacer(modifier = Modifier.height(12.dp))
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(10.dp))
                                        .background(Color(0x33EF4444))
                                        .border(BorderStroke(1.dp, LeashCritical), RoundedCornerShape(10.dp))
                                        .padding(horizontal = 12.dp, vertical = 6.dp)
                                ) {
                                    Text(
                                        text = "⚠ Session Tainted: ${sessionContext.taintSource ?: "README.md"}",
                                        color = LeashCritical,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                            }
                        }

                        // Glass Action Buttons matching "Set Up Wallet" and "Sign In Here"
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            GlassPillButton(
                                text = "Pair Laptop Daemon",
                                isPrimary = true,
                                icon = Icons.Default.SettingsEthernet,
                                onClick = onOpenPairing
                            )

                            GlassPillButton(
                                text = "Launch Demo Sandbox",
                                isPrimary = false,
                                icon = Icons.Default.PlayCircle,
                                onClick = onOpenDemo
                            )
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
