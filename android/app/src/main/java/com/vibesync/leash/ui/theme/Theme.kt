package com.vibesync.leash.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val LeashDarkBackground = Color(0xFF090B0E)
val LeashSurface = Color(0xFF131722)
val LeashSurfaceVariant = Color(0xFF1C2232)
val LeashBorder = Color(0xFF263045)

val LeashPrimary = Color(0xFF00E676)
val LeashPrimaryDark = Color(0xFF00A854)
val LeashCritical = Color(0xFFFF1744)
val LeashCriticalDark = Color(0xFFB71C1C)
val LeashWarning = Color(0xFFFF9100)
val LeashWarningDark = Color(0xFFE65100)
val LeashCyan = Color(0xFF00E5FF)
val LeashPurple = Color(0xFFB388FF)

val LeashTextPrimary = Color(0xFFF1F5F9)
val LeashTextSecondary = Color(0xFF94A3B8)
val LeashTextMuted = Color(0xFF64748B)

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
