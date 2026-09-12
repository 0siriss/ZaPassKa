package com.zapasska.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/** The palette of the desktop client, so both feel like one product. */
object Palette {
    val Background = Color(0xFF0D1117)
    val Panel = Color(0xFF161B22)
    val Border = Color(0xFF30363D)
    val Accent = Color(0xFF58A6FF)
    val Accent2 = Color(0xFF1F6FEB)
    val Text = Color(0xFFE6EDF3)
    val TextDim = Color(0xFF8B949E)
    val Danger = Color(0xFFF85149)
    val Success = Color(0xFF3FB950)
}

private val Scheme = darkColorScheme(
    primary = Palette.Accent,
    onPrimary = Color.White,
    secondary = Palette.Accent2,
    background = Palette.Background,
    onBackground = Palette.Text,
    surface = Palette.Panel,
    onSurface = Palette.Text,
    surfaceVariant = Palette.Panel,
    onSurfaceVariant = Palette.TextDim,
    error = Palette.Danger,
    outline = Palette.Border,
)

@Composable
fun ZaPassKaTheme(content: @Composable () -> Unit) {
    @Suppress("UNUSED_EXPRESSION") isSystemInDarkTheme()   // the app is dark either way
    MaterialTheme(colorScheme = Scheme, content = content)
}
