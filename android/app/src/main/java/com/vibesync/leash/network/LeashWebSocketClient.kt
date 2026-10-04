package com.vibesync.leash.network

import android.util.Log
import com.vibesync.leash.data.crypto.LeashCrypto
import com.vibesync.leash.data.model.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.*
import java.util.concurrent.TimeUnit

class LeashWebSocketClient(
    private var host: String,
    private var port: Int,
    private var sharedSecret: String,
    private val deviceId: String = "android_guard_01",
    private val deviceName: String = "Android Guard"
) {
    private val client = OkHttpClient.Builder()
        .readTimeout(0, TimeUnit.MILLISECONDS)
        .connectTimeout(5, TimeUnit.SECONDS)
        .build()

    private var webSocket: WebSocket? = null
    private val json = Json { ignoreUnknownKeys = true }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var heartbeatJob: Job? = null
    private var reconnectJob: Job? = null
    private var isExplicitDisconnect = false

    private val _connectionState = MutableStateFlow(ConnectionState.DISCONNECTED)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    private val _incomingActions = MutableSharedFlow<ActionBundle>(extraBufferCapacity = 64)
    val incomingActions: SharedFlow<ActionBundle> = _incomingActions.asSharedFlow()

    private val _incomingProvenance = MutableSharedFlow<ProvenanceEvent>(extraBufferCapacity = 64)
    val incomingProvenance: SharedFlow<ProvenanceEvent> = _incomingProvenance.asSharedFlow()

    private val _decisionAcks = MutableSharedFlow<DecisionAckPayload>(extraBufferCapacity = 64)
    val decisionAcks: SharedFlow<DecisionAckPayload> = _decisionAcks.asSharedFlow()

    fun updatePairing(newHost: String, newPort: Int, newSecret: String) {
        disconnect()
        host = newHost
        port = newPort
        sharedSecret = newSecret
        connect()
    }

    fun connect() {
        isExplicitDisconnect = false
        reconnectJob?.cancel()
        _connectionState.value = ConnectionState.CONNECTING

        val request = Request.Builder()
            .url("ws://$host:$port/ws")
            .build()

        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, response: Response) {
                Log.i("LeashClient", "Connected to Leash Daemon at $host:$port. Authenticating...")
                _connectionState.value = ConnectionState.AUTHENTICATING
                sendAuthHandshake(ws)
            }

            override fun onMessage(ws: WebSocket, text: String) {
                handleIncomingMessage(ws, text)
            }

            override fun onFailure(ws: WebSocket, t: Throwable, response: Response?) {
                Log.e("LeashClient", "WebSocket failure: ${t.message}")
                stopHeartbeat()
                handleDisconnectOrFailure()
            }

            override fun onClosed(ws: WebSocket, code: Int, reason: String) {
                Log.i("LeashClient", "WebSocket closed: $code / $reason")
                stopHeartbeat()
                handleDisconnectOrFailure()
            }
        })
    }

    private fun sendAuthHandshake(ws: WebSocket) {
        val nonce = LeashCrypto.generateNonce()
        val ts = System.currentTimeMillis() / 1000
        val canonBytes = LeashCrypto.canonicalAuthBytes(deviceId, deviceName, nonce, ts)
        val sig = LeashCrypto.sign(canonBytes, sharedSecret)

        val authMsg = """{"type":"auth","payload":{"device_id":"$deviceId","device_name":"$deviceName","nonce":"$nonce","ts":$ts,"sig":"$sig"}}"""
        ws.send(authMsg)
    }

    private fun handleIncomingMessage(ws: WebSocket, text: String) {
        try {
            val root = json.parseToJsonElement(text).jsonObject
            val type = root["type"]?.jsonPrimitive?.content
            val payloadStr = root["payload"].toString()

            when (type) {
                "auth_ack" -> {
                    val ack = json.decodeFromString<AuthAckPayload>(payloadStr)
                    Log.i("LeashClient", "Authenticated with Leash Daemon. Status: ${ack.status}")
                    _connectionState.value = ConnectionState.CONNECTED
                    startHeartbeat(ws)
                }
                "auth_error" -> {
                    Log.e("LeashClient", "Daemon rejected authentication: $payloadStr")
                    _connectionState.value = ConnectionState.DISCONNECTED
                    ws.close(4001, "Auth rejected")
                }
                "action_request" -> {
                    val bundle = json.decodeFromString<ActionBundle>(payloadStr)
                    // Verify request freshness and nonce
                    val req = bundle.request
                    val fresh = LeashCrypto.verifyFreshnessAndNonce(req.ts, req.nonce)
                    if (fresh) {
                        _incomingActions.tryEmit(bundle)
                    } else {
                        Log.w("LeashClient", "Rejected stale or replayed ActionRequest ${req.id}")
                    }
                }
                "provenance_event" -> {
                    val event = json.decodeFromString<ProvenanceEvent>(payloadStr)
                    val fresh = if (event.nonce.isNotEmpty()) {
                        LeashCrypto.verifyFreshnessAndNonce(event.ts, event.nonce)
                    } else true
                    if (fresh) {
                        _incomingProvenance.tryEmit(event)
                    } else {
                        Log.w("LeashClient", "Rejected stale or replayed ProvenanceEvent ${event.id}")
                    }
                }
                "decision_ack" -> {
                    val ack = json.decodeFromString<DecisionAckPayload>(payloadStr)
                    Log.i("LeashClient", "Decision confirmed by laptop for ${ack.action_id}: ${ack.verdict}")
                    _decisionAcks.tryEmit(ack)
                }
                "heartbeat_ack" -> {
                    // Heartbeat acknowledged by laptop daemon
                }
            }
        } catch (e: Exception) {
            Log.e("LeashClient", "Failed to parse message: $text", e)
        }
    }

    private fun startHeartbeat(ws: WebSocket) {
        stopHeartbeat()
        heartbeatJob = scope.launch {
            while (isActive && _connectionState.value == ConnectionState.CONNECTED) {
                delay(15_000)
                try {
                    val nonce = LeashCrypto.generateNonce()
                    val ts = System.currentTimeMillis() / 1000
                    val heartbeatMsg = """{"type":"heartbeat","payload":{"ts":$ts,"nonce":"$nonce"}}"""
                    ws.send(heartbeatMsg)
                } catch (e: Exception) {
                    Log.w("LeashClient", "Heartbeat send error: ${e.message}")
                }
            }
        }
    }

    private fun stopHeartbeat() {
        heartbeatJob?.cancel()
        heartbeatJob = null
    }

    private fun handleDisconnectOrFailure() {
        if (isExplicitDisconnect) {
            _connectionState.value = ConnectionState.DISCONNECTED
            return
        }

        _connectionState.value = ConnectionState.RECONNECTING
        reconnectJob?.cancel()
        reconnectJob = scope.launch {
            var delayMs = 2000L
            while (isActive && !isExplicitDisconnect && _connectionState.value != ConnectionState.CONNECTED) {
                delay(delayMs)
                Log.i("LeashClient", "Attempting reconnection to $host:$port...")
                connect()
                delayMs = (delayMs * 2).coerceAtMost(30000L)
            }
        }
    }

    fun sendDecision(
        actionId: String,
        sessionId: String,
        verdict: Verdict,
        by: DecidedBy,
        note: String? = null
    ): Boolean {
        val ws = webSocket
        if (ws == null || _connectionState.value != ConnectionState.CONNECTED) {
            Log.e("LeashClient", "Cannot send decision: Guard is not securely connected (Fail-Closed).")
            return false
        }

        val nonce = LeashCrypto.generateNonce()
        val ts = System.currentTimeMillis() / 1000
        val decId = "d_$nonce"
        val byStr = by.name.lowercase()
        val verdictStr = verdict.name.lowercase()
        val noteStr = note ?: ""

        val payloadBytes = LeashCrypto.canonicalDecisionBytes(
            actionId = actionId,
            by = byStr,
            id = decId,
            nonce = nonce,
            note = noteStr,
            session = sessionId,
            ts = ts,
            verdict = verdictStr
        )
        val sig = LeashCrypto.sign(payloadBytes, sharedSecret)

        val decision = Decision(
            id = decId,
            action_id = actionId,
            session = sessionId,
            ts = ts,
            nonce = nonce,
            verdict = verdict,
            by = by,
            note = note,
            sig = sig
        )

        val outMsg = """{"type":"decision","payload":${json.encodeToString(Decision.serializer(), decision)}}"""
        return ws.send(outMsg)
    }

    fun disconnect() {
        isExplicitDisconnect = true
        stopHeartbeat()
        reconnectJob?.cancel()
        webSocket?.close(1000, "User disconnected")
        webSocket = null
        _connectionState.value = ConnectionState.DISCONNECTED
    }
}
