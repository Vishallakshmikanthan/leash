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
        val jsonStr = buildString {
            append('{')
            append("\"action_id\":\"").append(escapeJson(actionId)).append("\",")
            append("\"by\":\"").append(escapeJson(by)).append("\",")
            append("\"id\":\"").append(escapeJson(id)).append("\",")
            append("\"nonce\":\"").append(escapeJson(nonce)).append("\",")
            append("\"note\":\"").append(escapeJson(note)).append("\",")
            append("\"session\":\"").append(escapeJson(session)).append("\",")
            append("\"ts\":").append(ts).append(',')
            append("\"verdict\":\"").append(escapeJson(verdict)).append("\"")
            append('}')
        }
        return jsonStr.toByteArray(Charsets.UTF_8)
    }

    fun canonicalAuthBytes(
        deviceId: String,
        deviceName: String,
        nonce: String,
        ts: Long
    ): ByteArray {
        val jsonStr = buildString {
            append('{')
            append("\"device_id\":\"").append(escapeJson(deviceId)).append("\",")
            append("\"device_name\":\"").append(escapeJson(deviceName)).append("\",")
            append("\"nonce\":\"").append(escapeJson(nonce)).append("\",")
            append("\"ts\":").append(ts)
            append('}')
        }
        return jsonStr.toByteArray(Charsets.UTF_8)
    }
}
