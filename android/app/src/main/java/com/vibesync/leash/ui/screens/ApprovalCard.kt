package com.vibesync.leash.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vibesync.leash.data.model.ActionBundle
import com.vibesync.leash.data.model.Severity
import com.vibesync.leash.ui.theme.LeashCritical
import com.vibesync.leash.ui.theme.LeashPrimary
import com.vibesync.leash.ui.theme.LeashWarning

@Composable
fun ApprovalCard(
    bundle: ActionBundle,
    onApprove: () -> Unit,
    onDeny: () -> Unit,
    modifier: Modifier = Modifier
) {
    val req = bundle.request
    val assessment = bundle.assessment

    val severityColor = when (assessment.severity) {
        Severity.CRITICAL, Severity.HIGH -> LeashCritical
        Severity.MEDIUM -> LeashWarning
        Severity.LOW -> LeashPrimary
    }

    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        modifier = modifier
            .fillMaxWidth()
            .padding(16.dp)
            .border(1.dp, severityColor.copy(alpha = 0.6f), RoundedCornerShape(16.dp))
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            // Header Row: Agent tag and Risk badge
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "AGENT: ${req.agent}",
                    style = MaterialTheme.typography.labelMedium,
                    color = Color.Gray
                )
                Surface(
                    color = severityColor.copy(alpha = 0.2f),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(
                        text = assessment.severity.name,
                        color = severityColor,
                        fontWeight = FontWeight.Bold,
                        fontSize = 12.sp,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Command snippet box
            val cmdText = req.command ?: req.target_path ?: req.tool_name ?: "Unknown Action"
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color.Black.copy(alpha = 0.4f), RoundedCornerShape(8.dp))
                    .padding(12.dp)
            ) {
                Text(
                    text = cmdText,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.sp,
                    color = Color(0xFF80CBC4)
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Taint escalation banner
            if (assessment.tainted_escalation || req.taint.tainted) {
                Surface(
                    color = LeashCritical.copy(alpha = 0.15f),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp)
                ) {
                    Text(
                        text = "⚠ Untrusted Source Influence: ${req.taint.source ?: "README.md"}${req.taint.line?.let { ":$it" } ?: ""}",
                        color = LeashCritical,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(8.dp)
                    )
                }
            }

            // Summary and Explanation
            Text(
                text = assessment.summary,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = assessment.why,
                style = MaterialTheme.typography.bodyMedium,
                color = Color.LightGray
            )

            Spacer(modifier = Modifier.height(20.dp))

            // Action Buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedButton(
                    onClick = onDeny,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = LeashCritical)
                ) {
                    Text("Deny")
                }
                Button(
                    onClick = onApprove,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = LeashPrimary)
                ) {
                    val label = if (assessment.severity == Severity.HIGH) "Approve (Fingerprint)" else "Approve"
                    Text(label)
                }
            }
        }
    }
}
