package com.vibesync.leash.data.crypto

import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.abs

object LeashCrypto {

    private val seenNonces = mutableMapOf<String, Long>()
    private const val MAX_DRIFT_SECONDS = 60L

    fun generateNonce(length: Int = 16): String {
        val random = SecureRandom()
        val bytes = ByteArray(length / 2)
        random.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun sign(payload: ByteArray, secret: String): String {
        val keySpec = SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256")
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(keySpec)
        val hmacBytes = mac.doFinal(payload)
        return hmacBytes.joinToString("") { "%02x".format(it) }
    }

    fun verify(payload: ByteArray, signature: String, secret: String): Boolean {
        val expected = sign(payload, secret)
        return expected.equals(signature, ignoreCase = true)
    }

    @Synchronized
    fun verifyFreshnessAndNonce(ts: Long, nonce: String, maxDriftSeconds: Long = MAX_DRIFT_SECONDS): Boolean {
        val now = System.currentTimeMillis() / 1000
        if (abs(now - ts) > maxDriftSeconds) {
            return false
        }
        val cutoff = now - maxDriftSeconds
        seenNonces.entries.removeIf { it.value < cutoff }
        if (seenNonces.containsKey(nonce)) {
            return false
        }
        seenNonces[nonce] = ts
        return true
    }

    private fun escapeJson(value: String): String {
        return value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\b", "\\b")
            .replace("\u000C", "\\f")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
    }

    fun canonicalJson(map: Map<String, Any?>): ByteArray {
        val sortedKeys = map.keys.sorted()
        val jsonStr = buildString {
            append('{')
            sortedKeys.forEachIndexed { index, key ->
                if (index > 0) append(',')
                append('"').append(escapeJson(key)).append("\":")
                val value = map[key]
                when (value) {
                    null -> append("null")
                    is Number -> append(value.toString())
                    is Boolean -> append(value.toString())
                    else -> append('"').append(escapeJson(value.toString())).append('"')
                }
            }
            append('}')
        }
        return jsonStr.toByteArray(Charsets.UTF_8)
    }

    fun canonicalDecisionBytes(
        actionId: String,
        by: String,
        id: String,
        nonce: String,
        note: String,
        session: String,
        ts: Long,
        verdict: String
    ): ByteArray {
        return canonicalJson(mapOf(
            "action_id" to actionId,
            "by" to by,
            "id" to id,
            "nonce" to nonce,
            "note" to note,
            "session" to session,
            "ts" to ts,
            "verdict" to verdict
        ))
    }

    fun canonicalSignedDecisionBytes(
        actionDigest: String,
        actionId: String,
        decidedBy: String,
        nonceServer: String,
        ts: Long,
        verdict: String
    ): ByteArray {
        return canonicalJson(mapOf(
            "action_digest" to actionDigest,
            "action_id" to actionId,
            "decided_by" to decidedBy,
            "nonce_server" to nonceServer,
            "ts" to ts,
            "verdict" to verdict
        ))
    }

    fun canonicalAuthBytes(
        deviceId: String,
        deviceName: String,
        nonce: String,
        ts: Long
    ): ByteArray {
        return canonicalJson(mapOf(
            "device_id" to deviceId,
            "device_name" to deviceName,
            "nonce" to nonce,
            "ts" to ts
        ))
    }
}
