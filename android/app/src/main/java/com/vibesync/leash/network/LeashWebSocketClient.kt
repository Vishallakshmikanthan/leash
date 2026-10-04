package com.vibesync.leash.network

import android.util.Log
import com.vibesync.leash.data.crypto.LeashCrypto
import com.vibesync.leash.data.model.*
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.*
import java.util.concurrent.TimeUnit

class LeashWebSocketClient(
    private val host: String,
    private val port: Int,
    private val sharedSecret: String
) {
    private val client = OkHttpClient.Builder()
        .readTimeout(0, TimeUnit.MILLISECONDS)
        .build()

    private var webSocket: WebSocket? = null
    private val json = Json { ignoreUnknownKeys = true }

    private val _incomingActions = MutableSharedFlow<ActionBundle>()
    val incomingActions: SharedFlow<ActionBundle> = _incomingActions.asSharedFlow()

    fun connect() {
        val request = Request.Builder()
            .url("ws://$host:$port")
            .build()

        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                Log.i("LeashClient", "Connected to Leash Daemon at $host:$port")
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                try {
                    val root = json.parseToJsonElement(text).jsonObject
                    val type = root["type"]?.jsonPrimitive?.content
                    if (type == "action_request") {
                        val payloadStr = root["payload"].toString()
                        val bundle = json.decodeFromString<ActionBundle>(payloadStr)
                        _incomingActions.tryEmit(bundle)
                    }
                } catch (e: Exception) {
                    Log.e("LeashClient", "Failed to parse message: $text", e)
                }
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.e("LeashClient", "WebSocket failure: ${t.message}")
            }
        })
    }

    fun sendDecision(
        actionId: String,
        sessionId: String,
        verdict: Verdict,
        by: DecidedBy,
        note: String? = null
    ) {
        val nonce = LeashCrypto.generateNonce()
        val ts = System.currentTimeMillis() / 1000

        // Build canonical string for signature
        val cleanMap = linkedMapOf(
            "action_id" to actionId,
            "by" to by.name.lowercase(),
            "id" to "d_$nonce",
            "nonce" to nonce,
            "note" to (note ?: ""),
            "session" to sessionId,
            "ts" to ts,
            "verdict" to verdict.name.lowercase()
        )
        val payloadBytes = json.encodeToString(kotlinx.serialization.serializer(), cleanMap).toByteArray(Charsets.UTF_8)
        val sig = LeashCrypto.sign(payloadBytes, sharedSecret)

        val decision = Decision(
            id = "d_$nonce",
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
        webSocket?.send(outMsg)
    }

    fun disconnect() {
        webSocket?.close(1000, "Normal closure")
        webSocket = null
    }
}
