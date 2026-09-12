package com.zapasska.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/** The palette of the desktop client, so both feel like one product. */
object Palette {
    val Background = Color(0xFF0D1117)
    val Panel = Color(0xFF161B22)
    val PanelHigh = Color(0xFF1C2128)
    val Border = Color(0xFF30363D)
    val Accent = Color(0xFF58A6FF)
    val Accent2 = Color(0xFF1F6FEB)
    val Text = Color(0xFFE6EDF3)
    val TextDim = Color(0xFF8B949E)
    val Danger = Color(0xFFF85149)
    val Success = Color(0xFF3FB950)
}

/**
 * Every role Material draws from has to be named here. Leaving one out does
 * not fall back to the palette: it falls back to Material's own purple, which
 * is how a stray violet button appears in an otherwise blue app.
 */
private val Scheme = darkColorScheme(
    primary = Palette.Accent,
    onPrimary = Color(0xFF06121F),
    primaryContainer = Palette.Accent2,
    onPrimaryContainer = Color.White,
    inversePrimary = Palette.Accent2,

    secondary = Palette.Accent,
    onSecondary = Color(0xFF06121F),
    secondaryContainer = Palette.PanelHigh,
    onSecondaryContainer = Palette.Text,

    tertiary = Palette.Accent,
    onTertiary = Color(0xFF06121F),
    tertiaryContainer = Palette.PanelHigh,
    onTertiaryContainer = Palette.Text,

    background = Palette.Background,
    onBackground = Palette.Text,

    surface = Palette.Background,
    onSurface = Palette.Text,
    surfaceVariant = Palette.Panel,
    onSurfaceVariant = Palette.TextDim,
    surfaceTint = Palette.Accent,
    inverseSurface = Palette.Text,
    inverseOnSurface = Palette.Background,

    surfaceBright = Palette.PanelHigh,
    surfaceDim = Palette.Background,
    surfaceContainerLowest = Palette.Background,
    surfaceContainerLow = Palette.Panel,
    surfaceContainer = Palette.Panel,
    surfaceContainerHigh = Palette.PanelHigh,
    surfaceContainerHighest = Palette.PanelHigh,

    error = Palette.Danger,
    onError = Color.White,
    errorContainer = Color(0xFF3B1517),
    onErrorContainer = Palette.Danger,

    outline = Palette.Border,
    outlineVariant = Palette.Border,
    scrim = Color(0xCC000000),
)

@Composable
fun ZaPassKaTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = Scheme, typography = Typography(), content = content)
}
