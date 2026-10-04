package com.vibesync.leash.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val LeashDarkBackground = Color(0xFF0F1117)
val LeashSurface = Color(0xFF1A1D26)
val LeashPrimary = Color(0xFF388E3C)
val LeashCritical = Color(0xFFD32F2F)
val LeashWarning = Color(0xFFF57C00)
val LeashCyan = Color(0xFF00ACC1)

private val DarkColorScheme = darkColorScheme(
    primary = LeashPrimary,
    background = LeashDarkBackground,
    surface = LeashSurface,
    error = LeashCritical
)

@Composable
fun LeashTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        typography = Typography(),
        content = content
    )
}
