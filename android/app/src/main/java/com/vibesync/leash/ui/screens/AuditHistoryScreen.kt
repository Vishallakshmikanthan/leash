package com.vibesync.leash.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vibesync.leash.data.model.AuditFeedItem
import com.vibesync.leash.data.model.Verdict
import com.vibesync.leash.ui.theme.*

@Composable
fun AuditHistoryScreen(
    feedItems: List<AuditFeedItem>,
    onRefresh: () -> Unit = {}
) {
    val context = LocalContext.current
    var selectedFilter by remember { mutableStateOf("ALL") }
    var searchQuery by remember { mutableStateOf("") }

    val filteredItems = remember(feedItems, selectedFilter, searchQuery) {
        feedItems.filter { item ->
            val matchesFilter = when (selectedFilter) {
                "ALLOWED" -> item.decision.verdict == Verdict.ALLOW
                "BLOCKED" -> item.decision.verdict == Verdict.DENY
                "TAINTED" -> item.action.taint.tainted
                else -> true
            }
            val matchesSearch = if (searchQuery.isBlank()) true else {
                val q = searchQuery.lowercase()
                (item.action.command ?: "").lowercase().contains(q) ||
                    (item.action.target_path ?: "").lowercase().contains(q) ||
                    item.action.agent.lowercase().contains(q) ||
                    item.assessment.category.lowercase().contains(q)
            }
            matchesFilter && matchesSearch
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(LeashDarkBackground)
            .padding(horizontal = 16.dp, vertical = 12.dp)
    ) {
        // Top Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "AUDIT TRAIL",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Black,
                    color = Color.White,
                    letterSpacing = 1.sp
                )
                Text(
                    text = "${feedItems.size} total verified actions recorded",
                    fontSize = 12.sp,
                    color = LeashTextSecondary
                )
            }

            IconButton(onClick = onRefresh) {
                Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = LeashCyan)
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        // Search Bar
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            placeholder = { Text("Search actions, commands, agents...", fontSize = 12.sp, color = LeashTextSecondary) },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = LeashTextSecondary, modifier = Modifier.size(18.dp)) },
            singleLine = true,
            shape = RoundedCornerShape(12.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedContainerColor = LeashSurface,
                unfocusedContainerColor = LeashSurface,
                focusedBorderColor = LeashCyan,
                unfocusedBorderColor = LeashBorder,
                focusedTextColor = Color.White,
                unfocusedTextColor = Color.White
            ),
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(10.dp))

        // Filter Chips Row
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            listOf("ALL", "BLOCKED", "ALLOWED", "TAINTED").forEach { filter ->
                val isSelected = selectedFilter == filter
                Surface(
                    color = if (isSelected) LeashCyan.copy(alpha = 0.2f) else LeashSurface,
                    shape = RoundedCornerShape(8.dp),
                    border = androidx.compose.foundation.BorderStroke(
                        1.dp,
                        if (isSelected) LeashCyan else LeashBorder
                    ),
                    modifier = Modifier.clickable { selectedFilter = filter }
                ) {
                    Text(
                        text = filter,
                        color = if (isSelected) LeashCyan else LeashTextSecondary,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                        fontSize = 11.sp,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Timeline List
        if (filteredItems.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = "No audit events match your filter.",
                    color = LeashTextSecondary,
                    fontSize = 13.sp
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                items(filteredItems, key = { it.action.id }) { item ->
                    AuditItemCard(item)
                }
            }
        }
    }
}

@Composable
private fun AuditItemCard(item: AuditFeedItem) {
    val context = LocalContext.current
    val isAllowed = item.decision.verdict == Verdict.ALLOW
    val statusColor = if (isAllowed) LeashPrimary else LeashCritical

    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = LeashSurface),
        border = androidx.compose.foundation.BorderStroke(1.dp, LeashBorder),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            // Header Row: Verdict Badge + Time + Agent
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Surface(
                        color = statusColor.copy(alpha = 0.18f),
                        shape = RoundedCornerShape(6.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, statusColor.copy(alpha = 0.5f))
                    ) {
                        Text(
                            text = if (isAllowed) "ALLOWED" else "BLOCKED",
                            color = statusColor,
                            fontWeight = FontWeight.Black,
                            fontSize = 10.sp,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "AGENT: ${item.action.agent}",
                        color = LeashTextSecondary,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }

                Text(
                    text = item.decision.by.name,
                    color = LeashTextSecondary,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold
                )
            }

            Spacer(modifier = Modifier.height(6.dp))

            // Command / Target text
            Text(
                text = item.action.command ?: item.action.target_path ?: "-",
                color = Color.White,
                fontSize = 12.sp,
                fontFamily = FontFamily.Monospace,
                maxLines = 2
            )

            Spacer(modifier = Modifier.height(4.dp))

            // Category & Reason
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = item.assessment.summary,
                    color = LeashTextSecondary,
                    fontSize = 11.sp,
                    maxLines = 1,
                    modifier = Modifier.weight(1f)
                )

                IconButton(
                    onClick = {
                        val clipMgr = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clipMgr.setPrimaryClip(ClipData.newPlainText("Action Command", item.action.command ?: ""))
                        Toast.makeText(context, "Command copied to clipboard", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.size(20.dp)
                ) {
                    Icon(Icons.Default.ContentCopy, contentDescription = "Copy", tint = LeashCyan, modifier = Modifier.size(13.dp))
                }
            }
        }
    }
}
