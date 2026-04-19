package com.vulnchat.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// ── Brand colours ────────────────────────────────────────────────────────────
// Primary: dark teal — references the security/defensive tooling aesthetic
// Error: coral red — used by blocked-message UI feedback
private val VulnTeal    = Color(0xFF1D9E75)
private val VulnTealDark = Color(0xFF0F6E56)
private val VulnRed     = Color(0xFFE24B4A)

private val LightColorScheme = lightColorScheme(
    primary          = VulnTeal,
    onPrimary        = Color.White,
    primaryContainer = Color(0xFFE1F5EE),
    secondary        = Color(0xFF534AB7),
    error            = VulnRed,
    background       = Color(0xFFFDFDFD),
    surface          = Color.White,
)

private val DarkColorScheme = darkColorScheme(
    primary          = Color(0xFF5DCAA5),
    onPrimary        = Color(0xFF04342C),
    primaryContainer = VulnTealDark,
    secondary        = Color(0xFFAFA9EC),
    error            = Color(0xFFF09595),
    background       = Color(0xFF121212),
    surface          = Color(0xFF1E1E1E),
)

@Composable
fun VulnChatTheme(
    darkTheme: Boolean = androidx.compose.foundation.isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme,
        content     = content
    )
}
