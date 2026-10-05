package com.vibesync.leash.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vibesync.leash.data.model.AuditFeedItem
import com.vibesync.leash.data.model.Severity
import com.vibesync.leash.data.model.Verdict
import com.vibesync.leash.ui.components.*
import com.vibesync.leash.ui.theme.*
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ActionFeedScreen(
    feedItems: List<AuditFeedItem>,
    modifier: Modifier = Modifier
) {
    var selectedFilter by remember { mutableStateOf("ALL") }
    var searchQuery by remember { mutableStateOf("") }
    var selectedTimeFilter by remember { mutableStateOf("Today") }

    val filteredItems = remember(feedItems, selectedFilter, searchQuery, selectedTimeFilter) {
        feedItems.filter { item ->
            val matchesFilter = when (selectedFilter) {
                "ALLOWED" -> item.decision.verdict == Verdict.ALLOW
                "DENIED" -> item.decision.verdict == Verdict.DENY
                "CRITICAL" -> item.bundle.assessment.severity == Severity.HIGH || item.bundle.assessment.severity == Severity.CRITICAL
                else -> true
            }
            val matchesSearch = if (searchQuery.isBlank()) true else {
                val q = searchQuery.lowercase()
                val cmd = (item.bundle.request.command ?: item.bundle.request.target_path ?: "").lowercase()
                cmd.contains(q) || item.bundle.request.agent.lowercase().contains(q) || item.bundle.assessment.category.lowercase().contains(q)
            }
            matchesFilter && matchesSearch
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(GlassBackgroundGradient)
            .padding(horizontal = 16.dp)
            .padding(top = 10.dp, bottom = 90.dp)
    ) {
        // Screen Header matching "All Transaction"
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .clip(CircleShape)
                    .background(Color(0x2EFFFFFF))
                    .border(BorderStroke(1.dp, Color(0x4DFFFFFF)), CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Default.KeyboardArrowLeft,
                    contentDescription = "Back",
                    tint = Color.White,
                    modifier = Modifier.size(20.dp)
                )
            }

            Spacer(modifier = Modifier.weight(1f))

            Text(
                text = "All Activity",
                fontSize = 16.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )

            Spacer(modifier = Modifier.weight(1f))

            Box(modifier = Modifier.size(36.dp)) // balance layout
        }

        Spacer(modifier = Modifier.height(10.dp))

        // Frosted Search Bar matching the reference UI
        GlassCard(
            modifier = Modifier.fillMaxWidth(),
            cornerRadius = 24.dp,
            backgroundColor = Color(0x331E293B),
            borderBrush = GlassCardBorderSubtle
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = Icons.Default.Search,
                    contentDescription = "Search",
                    tint = Color(0xFF94A3B8),
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(10.dp))
                TextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    placeholder = {
                        Text(
                            "Search Interceptions...",
                            color = Color(0xFF94A3B8),
                            fontSize = 13.sp
                        )
                    },
                    colors = TextFieldDefaults.colors(
                        focusedContainerColor = Color.Transparent,
                        unfocusedContainerColor = Color.Transparent,
                        focusedIndicatorColor = Color.Transparent,
                        unfocusedIndicatorColor = Color.Transparent,
                        cursorColor = Color.White,
                        focusedTextColor = Color.White,
                        unfocusedTextColor = Color.White
                    ),
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
                Icon(
                    imageVector = Icons.Default.CalendarToday,
                    contentDescription = "Filter Date",
                    tint = Color(0xFF94A3B8),
                    modifier = Modifier.size(16.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Time Filter Chips matching reference image (Today / Yesterday / This week / This Month)
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            listOf("Today", "Yesterday", "This week", "This Month").forEach { filterTag ->
                val isSelected = selectedTimeFilter == filterTag
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(16.dp))
                        .background(if (isSelected) Color.White else Color(0x331E293B))
                        .border(
                            BorderStroke(1.dp, if (isSelected) Color.White else Color(0x33FFFFFF)),
                            RoundedCornerShape(16.dp)
                        )
                        .clickable { selectedTimeFilter = filterTag }
                        .padding(vertical = 6.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = filterTag,
                        fontSize = 10.sp,
                        fontWeight = if (isSelected) FontWeight.ExtraBold else FontWeight.Medium,
                        color = if (isSelected) Color(0xFF0F172A) else Color(0xFFCBD5E1),
                        maxLines = 1
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Secondary Tag Filter (ALL / ALLOWED / DENIED / CRITICAL)
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            listOf("ALL", "ALLOWED", "DENIED", "CRITICAL").forEach { filterTag ->
                val isSelected = selectedFilter == filterTag
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(10.dp))
                        .background(if (isSelected) Color(0xFF10B981) else Color(0x331E293B))
                        .border(
                            BorderStroke(1.dp, if (isSelected) Color(0xFF10B981) else Color(0x26FFFFFF)),
                            RoundedCornerShape(10.dp)
                        )
                        .clickable { selectedFilter = filterTag }
                        .padding(horizontal = 10.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = filterTag,
                        fontSize = 10.sp,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                        color = if (isSelected) Color.White else Color(0xFF94A3B8)
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        if (filteredItems.isEmpty()) {
            GlassCard(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                cornerRadius = 20.dp,
                backgroundColor = Color(0x331E293B),
                borderBrush = GlassCardBorderSubtle
            ) {
                Column(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        imageVector = Icons.Default.History,
                        contentDescription = "No history",
                        tint = Color(0x66FFFFFF),
                        modifier = Modifier.size(44.dp)
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = "No Interceptions Recorded",
                        fontWeight = FontWeight.Bold,
                        color = Color.White,
                        fontSize = 14.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Agent shell and tool actions will appear here in real time.",
                        fontSize = 11.sp,
                        color = Color(0x99FFFFFF)
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                contentPadding = PaddingValues(bottom = 12.dp)
            ) {
                items(filteredItems, key = { it.id }) { item ->
                    FeedItemRow(item = item)
                }
            }
        }
    }
}

@Composable
fun FeedItemRow(item: AuditFeedItem) {
    val req = item.bundle.request
    val assessment = item.bundle.assessment
    val decision = item.decision

    var expanded by remember { mutableStateOf(false) }

    val isAllowed = decision.verdict == Verdict.ALLOW
    val verdictColor = if (isAllowed) LeashPrimary else LeashCritical
    val timeFormat = SimpleDateFormat("dd-MM-yy HH:mm", Locale.getDefault())
    val formattedTime = timeFormat.format(Date(item.timestamp))

    val icon = when {
        assessment.category.contains("package", ignoreCase = true) -> Icons.Default.Inventory2
        assessment.category.contains("secret", ignoreCase = true) -> Icons.Default.Lock
        assessment.category.contains("injection", ignoreCase = true) || assessment.tainted_escalation -> Icons.Default.BugReport
        else -> Icons.Default.Terminal
    }

    val cmd = req.command ?: req.target_path ?: req.tool_name ?: "Unknown Action"

    Column(modifier = Modifier.fillMaxWidth()) {
        GlassActivityRow(
            title = cmd,
            timestamp = "$formattedTime • ${req.agent} • ${assessment.category}",
            verdictLabel = if (isAllowed) "SAFE" else "BLOCKED",
            isBlocked = !isAllowed,
            icon = icon,
            badgeColor = verdictColor,
            onClick = { expanded = !expanded }
        )

        AnimatedVisibility(visible = expanded) {
            GlassCard(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 4.dp, vertical = 2.dp),
                cornerRadius = 14.dp,
                backgroundColor = Color(0x401E293B),
                borderBrush = GlassCardBorderSubtle
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "Risk Summary: ${assessment.summary}",
                        fontWeight = FontWeight.Bold,
                        color = Color.White,
                        fontSize = 11.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Why: ${assessment.why}",
                        color = Color(0xCCFFFFFF),
                        fontSize = 11.sp,
                        lineHeight = 16.sp
                    )
                    assessment.safer_alternative?.takeIf { it.isNotBlank() && it != "None required." }?.let { alt ->
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Safer Alternative: $alt",
                            color = LeashCyan,
                            fontSize = 10.sp
                        )
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "Action ID: ${req.id} • Latency: ${item.latencyMs}ms • By: ${decision.by.name}",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp,
                        color = Color(0x80FFFFFF)
                    )
                }
            }
        }
    }
}
