package com.vibesync.leash.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vibesync.leash.ui.theme.*

/**
 * Frosted Glassmorphism Container with specular light border reflection.
 */
@Composable
fun GlassCard(
    modifier: Modifier = Modifier,
    cornerRadius: Dp = 22.dp,
    backgroundColor: Color = GlassCardBgMid,
    borderBrush: Brush = GlassCardBorder,
    borderWidth: Dp = 1.dp,
    onClick: (() -> Unit)? = null,
    content: @Composable BoxScope.() -> Unit
) {
    val shape = RoundedCornerShape(cornerRadius)
    val clickableModifier = if (onClick != null) {
        Modifier.clickable(
            interactionSource = remember { MutableInteractionSource() },
            indication = ripple(color = Color.White.copy(alpha = 0.2f)),
            onClick = onClick
        )
    } else Modifier

    Box(
        modifier = modifier
            .shadow(
                elevation = 8.dp,
                shape = shape,
                ambientColor = Color.Black.copy(alpha = 0.15f),
                spotColor = Color.Black.copy(alpha = 0.25f)
            )
            .clip(shape)
            .background(backgroundColor)
            .border(BorderStroke(borderWidth, borderBrush), shape)
            .then(clickableModifier),
        content = content
    )
}

/**
 * Capsule Segmented Tab Bar matching the reference UI (Today / This Week / This Month / All Time).
 */
@Composable
fun GlassSegmentedTabs(
    tabs: List<String>,
    selectedIndex: Int,
    onTabSelected: (Int) -> Unit,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(30.dp))
            .background(Color(0x2EFFFFFF))
            .border(BorderStroke(1.dp, Color(0x40FFFFFF)), RoundedCornerShape(30.dp))
            .padding(4.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            tabs.forEachIndexed { index, title ->
                val isSelected = index == selectedIndex
                val animColor by animateColorAsState(
                    targetValue = if (isSelected) Color.White else Color.Transparent,
                    animationSpec = tween(durationMillis = 220),
                    label = "tab_bg"
                )
                val animTextColor by animateColorAsState(
                    targetValue = if (isSelected) Color(0xFF0F172A) else Color(0xFFCBD5E1),
                    animationSpec = tween(durationMillis = 220),
                    label = "tab_text"
                )

                Box(
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(24.dp))
                        .background(animColor)
                        .clickable(
                            interactionSource = remember { MutableInteractionSource() },
                            indication = null
                        ) { onTabSelected(index) }
                        .padding(vertical = 8.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = title,
                        color = animTextColor,
                        fontWeight = if (isSelected) FontWeight.ExtraBold else FontWeight.Medium,
                        fontSize = 11.sp
                    )
                }
            }
        }
    }
}

/**
 * Smooth Bezier Wave Chart matching the Overview card in the reference image.
 */
@Composable
fun GlassWaveChart(
    modifier: Modifier = Modifier,
    lineColor: Color = Color(0xFF38BDF8),
    peakLabel: String = "14:20",
    peakValue: String = "3 Blocked"
) {
    val transition = rememberInfiniteTransition(label = "wave_pulse")
    val pulseAlpha by transition.animateFloat(
        initialValue = 0.6f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(1500, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse_alpha"
    )

    Column(modifier = modifier.fillMaxWidth()) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(130.dp)
        ) {
            Canvas(modifier = Modifier.fillMaxSize()) {
                val w = size.width
                val h = size.height

                val path = Path().apply {
                    moveTo(0f, h * 0.45f)
                    cubicTo(w * 0.15f, h * 0.25f, w * 0.32f, h * 0.70f, w * 0.48f, h * 0.28f)
                    cubicTo(w * 0.65f, h * -0.05f, w * 0.82f, h * 0.60f, w, h * 0.35f)
                }

                val fillPath = Path().apply {
                    addPath(path)
                    lineTo(w, h)
                    lineTo(0f, h)
                    close()
                }

                // Gradient fill underneath
                drawPath(
                    path = fillPath,
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            lineColor.copy(alpha = 0.40f),
                            lineColor.copy(alpha = 0.00f)
                        ),
                        startY = 0f,
                        endY = h
                    )
                )

                // Smooth glowing stroke
                drawPath(
                    path = path,
                    color = lineColor,
                    style = Stroke(width = 3.5f, cap = StrokeCap.Round)
                )

                // Peak indicator coordinate (approx at w * 0.48f, h * 0.28f)
                val peakX = w * 0.48f
                val peakY = h * 0.28f

                // Vertical dashed guide line
                drawLine(
                    color = Color.White.copy(alpha = 0.35f),
                    start = Offset(peakX, peakY),
                    end = Offset(peakX, h),
                    strokeWidth = 1.5f,
                    pathEffect = PathEffect.dashPathEffect(floatArrayOf(8f, 6f))
                )

                // Glowing point
                drawCircle(
                    color = Color(0xFF0F172A),
                    radius = 9f,
                    center = Offset(peakX, peakY)
                )
                drawCircle(
                    color = lineColor.copy(alpha = pulseAlpha),
                    radius = 5.5f,
                    center = Offset(peakX, peakY)
                )
            }

            // Floating Tooltip Badge positioned at center peak
            Box(
                modifier = Modifier
                    .align(Alignment.TopCenter)
                    .offset(y = 2.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(Color(0xFF0F172A))
                    .border(BorderStroke(1.dp, Color(0x4038BDF8)), RoundedCornerShape(8.dp))
                    .padding(horizontal = 8.dp, vertical = 4.dp)
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = peakLabel,
                        color = Color(0xFF94A3B8),
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Medium
                    )
                    Text(
                        text = peakValue,
                        color = Color.White,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }

        // Days of week row
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            listOf("S", "M", "T", "W", "T", "F", "S").forEachIndexed { idx, day ->
                val isPeakDay = idx == 3 // Wednesday peak
                Text(
                    text = day,
                    fontSize = 11.sp,
                    fontWeight = if (isPeakDay) FontWeight.ExtraBold else FontWeight.Medium,
                    color = if (isPeakDay) Color.White else Color(0xFF94A3B8)
                )
            }
        }
    }
}

/**
 * 2x2 Bento Stat Card matching the reference cards.
 */
@Composable
fun GlassBentoCard(
    title: String,
    value: String,
    chipText: String,
    icon: ImageVector,
    modifier: Modifier = Modifier,
    iconColor: Color = Color.White,
    chipColor: Color = Color(0x99FFFFFF)
) {
    GlassCard(
        modifier = modifier.height(115.dp),
        cornerRadius = 20.dp,
        backgroundColor = Color(0x331E293B),
        borderBrush = GlassCardBorderSubtle
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(14.dp),
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = title,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = Color(0xFFCBD5E1)
                )
                Box(
                    modifier = Modifier
                        .size(26.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(Color(0x331E293B)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = icon,
                        contentDescription = null,
                        tint = iconColor,
                        modifier = Modifier.size(15.dp)
                    )
                }
            }

            Text(
                text = value,
                fontSize = 22.sp,
                fontWeight = FontWeight.Black,
                color = Color.White,
                letterSpacing = (-0.5).sp
            )

            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(Color(0x261E293B))
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                ) {
                    Text(
                        text = chipText,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold,
                        color = chipColor
                    )
                }
            }
        }
    }
}

/**
 * Glass Transaction / Action Row for the Activity Feed (Screen 3 style).
 */
@Composable
fun GlassActivityRow(
    title: String,
    timestamp: String,
    verdictLabel: String,
    isBlocked: Boolean,
    icon: ImageVector,
    modifier: Modifier = Modifier,
    badgeColor: Color = if (isBlocked) LeashCritical else LeashPrimary,
    onClick: (() -> Unit)? = null
) {
    GlassCard(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        cornerRadius = 18.dp,
        backgroundColor = Color(0x331E293B),
        borderBrush = GlassCardBorderSubtle,
        onClick = onClick
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f)
            ) {
                // Circular Frosted Icon Badge
                Box(
                    modifier = Modifier
                        .size(42.dp)
                        .clip(CircleShape)
                        .background(Color(0x331E293B))
                        .border(BorderStroke(1.dp, Color(0x66FFFFFF)), CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = icon,
                        contentDescription = null,
                        tint = Color.White,
                        modifier = Modifier.size(20.dp)
                    )
                }

                Spacer(modifier = Modifier.width(12.dp))

                Column {
                    Text(
                        text = title,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White,
                        maxLines = 1
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = timestamp,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Normal,
                        color = Color(0xFF94A3B8)
                    )
                }
            }

            Spacer(modifier = Modifier.width(8.dp))

            // Right Risk/Verdict Pill Badge
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .background(badgeColor.copy(alpha = 0.22f))
                    .border(BorderStroke(1.dp, badgeColor.copy(alpha = 0.6f)), RoundedCornerShape(8.dp))
                    .padding(horizontal = 8.dp, vertical = 4.dp)
            ) {
                Text(
                    text = verdictLabel,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.ExtraBold,
                    color = badgeColor
                )
            }
        }
    }
}

/**
 * Floating Glass Bottom Navigation Dock matching the reference image.
 */
@Composable
fun GlassFloatingDock(
    currentTab: Int,
    pendingBadgeCount: Int = 0,
    onTabSelected: (Int) -> Unit,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 28.dp, vertical = 14.dp),
        contentAlignment = Alignment.Center
    ) {
        Box(
            modifier = Modifier
                .shadow(
                    elevation = 16.dp,
                    shape = RoundedCornerShape(36.dp),
                    ambientColor = Color.Black.copy(alpha = 0.25f),
                    spotColor = Color.Black.copy(alpha = 0.35f)
                )
                .clip(RoundedCornerShape(36.dp))
                .background(Color(0xD91E293B))
                .border(
                    BorderStroke(
                        1.dp,
                        Brush.linearGradient(
                            listOf(
                                Color(0x80FFFFFF),
                                Color(0x26FFFFFF)
                            )
                        )
                    ),
                    RoundedCornerShape(36.dp)
                )
                .padding(horizontal = 10.dp, vertical = 6.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                // Tab 0: Guard Shield
                DockItem(
                    icon = Icons.Default.Shield,
                    label = "Guard",
                    isSelected = currentTab == 0,
                    badgeCount = pendingBadgeCount,
                    onClick = { onTabSelected(0) }
                )

                // Tab 1: Analytics / Overview
                DockItem(
                    icon = Icons.Default.Analytics,
                    label = "Analytics",
                    isSelected = currentTab == 1,
                    onClick = { onTabSelected(1) }
                )

                // Tab 2: Activity / Audit Feed
                DockItem(
                    icon = Icons.Default.ListAlt,
                    label = "Activity",
                    isSelected = currentTab == 2,
                    onClick = { onTabSelected(2) }
                )

                // Tab 3: Profile / Settings
                DockItem(
                    icon = Icons.Default.Person,
                    label = "Profile",
                    isSelected = currentTab == 3,
                    onClick = { onTabSelected(3) }
                )
            }
        }
    }
}

@Composable
private fun DockItem(
    icon: ImageVector,
    label: String,
    isSelected: Boolean,
    badgeCount: Int = 0,
    onClick: () -> Unit
) {
    val animBgColor by animateColorAsState(
        targetValue = if (isSelected) Color.White else Color.Transparent,
        animationSpec = spring(stiffness = Spring.StiffnessMediumLow),
        label = "dock_bg"
    )
    val animContentColor by animateColorAsState(
        targetValue = if (isSelected) Color(0xFF0F172A) else Color(0xFF94A3B8),
        animationSpec = spring(stiffness = Spring.StiffnessMediumLow),
        label = "dock_content"
    )

    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(28.dp))
            .background(animBgColor)
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
                onClick = onClick
            )
            .padding(horizontal = if (isSelected) 14.dp else 10.dp, vertical = 8.dp),
        contentAlignment = Alignment.Center
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center
        ) {
            BadgedBox(
                badge = {
                    if (badgeCount > 0) {
                        Badge(containerColor = LeashCritical) {
                            Text(
                                text = badgeCount.toString(),
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 9.sp
                            )
                        }
                    }
                }
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = label,
                    tint = animContentColor,
                    modifier = Modifier.size(18.dp)
                )
            }

            AnimatedVisibility(visible = isSelected) {
                Row {
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = label,
                        color = animContentColor,
                        fontWeight = FontWeight.Bold,
                        fontSize = 11.sp
                    )
                }
            }
        }
    }
}

/**
 * Solid or Glass Pill Button (like "Set Up Wallet" and "Sign In Here" in screen 1).
 */
@Composable
fun GlassPillButton(
    text: String,
    isPrimary: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null
) {
    val shape = RoundedCornerShape(30.dp)
    val bgModifier = if (isPrimary) {
        Modifier
            .background(Color.White, shape)
            .shadow(6.dp, shape, ambientColor = Color.Black.copy(alpha = 0.2f))
    } else {
        Modifier
            .background(Color(0x26FFFFFF), shape)
            .border(BorderStroke(1.5.dp, Color(0x66FFFFFF)), shape)
    }

    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(52.dp)
            .clip(shape)
            .then(bgModifier)
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = ripple(color = if (isPrimary) Color.Black.copy(alpha = 0.1f) else Color.White.copy(alpha = 0.2f)),
                onClick = onClick
            ),
        contentAlignment = Alignment.Center
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center
        ) {
            if (icon != null) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = if (isPrimary) Color(0xFF0F172A) else Color.White,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
            }
            Text(
                text = text,
                color = if (isPrimary) Color(0xFF0F172A) else Color.White,
                fontSize = 14.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 0.2.sp
            )
        }
    }
}
