package com.vibesync.leash.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vibesync.leash.data.model.DemoScenario
import com.vibesync.leash.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DemoSandboxSheet(
    onTriggerScenario: (DemoScenario) -> Unit,
    onDismiss: () -> Unit
) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        containerColor = LeashSurface,
        dragHandle = { BottomSheetDefaults.DragHandle(color = LeashBorder) }
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 12.dp)
                .padding(bottom = 32.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "LIVE HACKATHON DEMO SANDBOX",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.ExtraBold,
                        color = LeashCyan
                    )
                    Text(
                        text = "Inject realistic scenarios to demonstrate Guard behavior to judges",
                        style = MaterialTheme.typography.bodySmall,
                        color = LeashTextSecondary
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            DemoScenarioItem(
                scenario = DemoScenario.PROMPT_INJECTION,
                badgeColor = LeashCritical,
                badgeLabel = "CRITICAL / TAINT",
                icon = Icons.Default.BugReport,
                onClick = {
                    onTriggerScenario(DemoScenario.PROMPT_INJECTION)
                    onDismiss()
                }
            )

            Spacer(modifier = Modifier.height(10.dp))

            DemoScenarioItem(
                scenario = DemoScenario.PACKAGE_GATE,
                badgeColor = LeashWarning,
                badgeLabel = "PACKAGE GATE",
                icon = Icons.Default.Inventory2,
                onClick = {
                    onTriggerScenario(DemoScenario.PACKAGE_GATE)
                    onDismiss()
                }
            )

            Spacer(modifier = Modifier.height(10.dp))

            DemoScenarioItem(
                scenario = DemoScenario.SECRET_EXPOSURE,
                badgeColor = LeashCritical,
                badgeLabel = "SECRET FENCE",
                icon = Icons.Default.Lock,
                onClick = {
                    onTriggerScenario(DemoScenario.SECRET_EXPOSURE)
                    onDismiss()
                }
            )

            Spacer(modifier = Modifier.height(10.dp))

            DemoScenarioItem(
                scenario = DemoScenario.NORMAL_DEV,
                badgeColor = LeashPrimary,
                badgeLabel = "AUTO-ALLOW",
                icon = Icons.Default.PlayArrow,
                onClick = {
                    onTriggerScenario(DemoScenario.NORMAL_DEV)
                    onDismiss()
                }
            )
        }
    }
}

@Composable
fun DemoScenarioItem(
    scenario: DemoScenario,
    badgeColor: Color,
    badgeLabel: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    onClick: () -> Unit
) {
    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = LeashDarkBackground),
        border = androidx.compose.foundation.BorderStroke(1.dp, LeashBorder),
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
    ) {
        Row(
            modifier = Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Surface(
                color = badgeColor.copy(alpha = 0.2f),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.size(40.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = icon,
                        contentDescription = null,
                        tint = badgeColor,
                        modifier = Modifier.size(20.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = scenario.title,
                        fontWeight = FontWeight.Bold,
                        fontSize = 13.sp,
                        color = LeashTextPrimary
                    )
                    Surface(
                        color = badgeColor.copy(alpha = 0.15f),
                        shape = RoundedCornerShape(4.dp)
                    ) {
                        Text(
                            text = badgeLabel,
                            color = badgeColor,
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }
                }
                Spacer(modifier = Modifier.height(3.dp))
                Text(
                    text = scenario.description,
                    color = LeashTextSecondary,
                    fontSize = 11.sp,
                    lineHeight = 15.sp
                )
            }
        }
    }
}
