package com.vibesync.leash.data.repository

import android.content.Context
import android.util.Log
import com.vibesync.leash.data.model.AuditFeedItem
import com.vibesync.leash.data.model.ExecutionResultModel
import com.vibesync.leash.data.model.SessionSummary
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File

/**
 * AuditRepository - Lightweight, privacy-preserving, persistent storage
 * for Leash audit history on Android Guard. Operates entirely locally with zero cloud dependency.
 */
class AuditRepository(private val context: Context? = null) {

    private val json = Json { ignoreUnknownKeys = true; prettyPrint = false }
    private val memoryFeedItems = mutableListOf<AuditFeedItem>()
    private var memorySummary: SessionSummary? = null

    private fun getSessionAuditFile(sessionId: String): File? {
        val dir = context?.filesDir ?: return null
        return File(dir, "leash_audit_${sessionId.replace("[^a-zA-Z0-9_-]".toRegex(), "_")}.jsonl")
    }

    private fun getSessionSummaryFile(sessionId: String): File? {
        val dir = context?.filesDir ?: return null
        return File(dir, "leash_summary_${sessionId.replace("[^a-zA-Z0-9_-]".toRegex(), "_")}.json")
    }

    @Synchronized
    fun saveFeedItem(item: AuditFeedItem) {
        memoryFeedItems.removeAll { it.id == item.id || it.bundle.request.id == item.bundle.request.id }
        memoryFeedItems.add(0, item)

        val file = getSessionAuditFile(item.bundle.request.session) ?: return
        try {
            val line = json.encodeToString(item) + "\n"
            file.appendText(line)
        } catch (e: Exception) {
            Log.e("AuditRepository", "Failed to persist audit item ${item.id}", e)
        }
    }

    @Synchronized
    fun updateExecutionResult(actionId: String, result: ExecutionResultModel) {
        val index = memoryFeedItems.indexOfFirst { it.bundle.request.id == actionId }
        if (index >= 0) {
            val existing = memoryFeedItems[index]
            val updated = existing.copy(executionResult = result)
            memoryFeedItems[index] = updated

            val file = getSessionAuditFile(existing.bundle.request.session) ?: return
            rewriteAllFeedItems(file, memoryFeedItems.filter { it.bundle.request.session == existing.bundle.request.session })
        }
    }

    @Synchronized
    fun loadFeedItems(sessionId: String): List<AuditFeedItem> {
        val file = getSessionAuditFile(sessionId)
        if (file == null || !file.exists()) {
            return memoryFeedItems.filter { it.bundle.request.session == sessionId }
        }

        try {
            val items = mutableListOf<AuditFeedItem>()
            file.forEachLine { line ->
                if (line.isNotBlank()) {
                    try {
                        val item = json.decodeFromString<AuditFeedItem>(line)
                        items.add(0, item) // newest first
                    } catch (e: Exception) {
                        Log.w("AuditRepository", "Skipping corrupted audit line: $line")
                    }
                }
            }
            // Sync with memory
            for (item in items) {
                if (memoryFeedItems.none { it.id == item.id }) {
                    memoryFeedItems.add(item)
                }
            }
            return items
        } catch (e: Exception) {
            Log.e("AuditRepository", "Error reading audit file for $sessionId", e)
            return memoryFeedItems.filter { it.bundle.request.session == sessionId }
        }
    }

    @Synchronized
    fun saveSessionSummary(summary: SessionSummary) {
        memorySummary = summary
        val file = getSessionSummaryFile(summary.session_id) ?: return
        try {
            val content = json.encodeToString(summary)
            file.writeText(content)
        } catch (e: Exception) {
            Log.e("AuditRepository", "Failed to save session summary for ${summary.session_id}", e)
        }
    }

    @Synchronized
    fun loadSessionSummary(sessionId: String): SessionSummary? {
        val file = getSessionSummaryFile(sessionId)
        if (file != null && file.exists()) {
            try {
                val content = file.readText()
                if (content.isNotBlank()) {
                    return json.decodeFromString<SessionSummary>(content)
                }
            } catch (e: Exception) {
                Log.w("AuditRepository", "Error loading session summary for $sessionId", e)
            }
        }
        return if (memorySummary?.session_id == sessionId) memorySummary else null
    }

    private fun rewriteAllFeedItems(file: File, items: List<AuditFeedItem>) {
        try {
            val content = items.reversed().joinToString("\n") { json.encodeToString(it) } + "\n"
            file.writeText(content)
        } catch (e: Exception) {
            Log.e("AuditRepository", "Failed to rewrite audit file", e)
        }
    }
}
