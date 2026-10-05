package com.vibesync.leash.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color

// Core Theme Colors
val LeashDarkBackground = Color(0xFF0F172A)
val LeashSurface = Color(0xFF1E293B)
val LeashSurfaceVariant = Color(0xFF334155)
val LeashBorder = Color(0x33CBD5E1)

val LeashPrimary = Color(0xFF10B981)
val LeashPrimaryDark = Color(0xFF047857)
val LeashCritical = Color(0xFFEF4444)
val LeashCriticalDark = Color(0xFFB91C1C)
val LeashWarning = Color(0xFFF59E0B)
val LeashWarningDark = Color(0xFFD97706)
val LeashCyan = Color(0xFF06B6D4)
val LeashPurple = Color(0xFF8B5CF6)

val LeashTextPrimary = Color(0xFFF8FAFC)
val LeashTextSecondary = Color(0xFF94A3B8)
val LeashTextMuted = Color(0xFF64748B)

// Glassmorphism Design Tokens - High-Contrast Dark Frosted Glass
val GlassBgTop = Color(0xFF1E293B)      // Slate 800
val GlassBgMid = Color(0xFF141F2D)      // Deep Navy Slate
val GlassBgDeep = Color(0xFF0F172A)     // Slate 900
val GlassBgBottom = Color(0xFF0A0F18)   // Midnight Obsidian

val GlassBackgroundGradient = Brush.verticalGradient(
    listOf(
        GlassBgTop,
        GlassBgMid,
        GlassBgDeep,
        GlassBgBottom
    )
)

val GlassCardBgLight = Color(0x381E293B)
val GlassCardBgMid = Color(0x2E1E293B)
val GlassCardBgDark = Color(0x1F1E293B)

val GlassCardBorder = Brush.linearGradient(
    listOf(
        Color(0x66FFFFFF),
        Color(0x2638BDF8),
        Color(0x1AFFFFFF)
    )
)

val GlassCardBorderSubtle = Brush.linearGradient(
    listOf(
        Color(0x40FFFFFF),
        Color(0x14FFFFFF)
    )
)

val GlassDarkCardBg = Color(0xB31E293B)
val GlassDarkCardBorder = Color(0x33FFFFFF)

val GlassPillBackground = Color(0x24FFFFFF)
val GlassPillActiveBg = Color(0xFFFFFFFF)
val GlassPillActiveText = Color(0xFF0F172A)

val GlassChartLine = Color(0xFF38BDF8)
val GlassChartFill = Brush.verticalGradient(
    listOf(
        Color(0x6638BDF8),
        Color(0x0038BDF8)
    )
)

val GlassHeroOverlay = Brush.verticalGradient(
    listOf(
        Color.Transparent,
        Color(0x660F172A),
        Color(0xE60A0F18)
    )
)

private val DarkColorScheme = darkColorScheme(
    primary = LeashPrimary,
    onPrimary = Color.Black,
    primaryContainer = LeashPrimaryDark.copy(alpha = 0.25f),
    onPrimaryContainer = LeashPrimary,
    secondary = LeashCyan,
    onSecondary = Color.Black,
    tertiary = LeashWarning,
    background = LeashDarkBackground,
    onBackground = LeashTextPrimary,
    surface = LeashSurface,
    onSurface = LeashTextPrimary,
    surfaceVariant = LeashSurfaceVariant,
    onSurfaceVariant = LeashTextSecondary,
    error = LeashCritical,
    onError = Color.White,
    errorContainer = LeashCriticalDark.copy(alpha = 0.25f),
    onErrorContainer = LeashCritical,
    outline = LeashBorder
)

@Composable
fun LeashTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        typography = Typography(),
        content = content
    )
}

