package com.vibesync.leash

import com.vibesync.leash.data.crypto.LeashCrypto
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

class GoldenVectorsTest {

    @Test
    fun testGoldenCanonicalVectors() {
        // Find contracts/golden/canonical_vectors.json relative to repository root
        val possiblePaths = listOf(
            File("../../contracts/golden/canonical_vectors.json"),
            File("../contracts/golden/canonical_vectors.json"),
            File("contracts/golden/canonical_vectors.json")
        )
        val file = possiblePaths.firstOrNull { it.exists() }
            ?: throw IllegalStateException("Cannot find contracts/golden/canonical_vectors.json")

        val jsonContent = file.readText(Charsets.UTF_8)
        val array = JSONArray(jsonContent)

        for (i in 0 until array.length()) {
            val item = array.getJSONObject(i)
            val caseId = item.getString("id")
            val inputObj = item.getJSONObject("input")
            val expected = item.getString("expected_canonical_sorted")

            val map = mutableMapOf<String, Any?>()
            val keys = inputObj.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                map[key] = inputObj.get(key)
            }

            val actualBytes = LeashCrypto.canonicalJson(map)
            val actual = String(actualBytes, Charsets.UTF_8)
            assertEquals("Failed for case $caseId", expected, actual)
        }
    }
}
