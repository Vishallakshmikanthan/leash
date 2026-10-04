package com.vibesync.leash.data.crypto

import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object LeashCrypto {

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
}
