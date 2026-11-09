package app.agentlink.ui

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import kotlin.math.max
import kotlin.math.min

/** Tide navy. Filled buttons and focused controls; white or ink text stays above 7:1. */
private val Tide = Color(0xFF1F4E79)

/** Existing dark-theme primary. Dark ink on this blue stays above 7:1. */
private val TideLight = Color(0xFF9EC1DE)

/** Soft cyan brand, same as the launcher plate. Container accent only, never body text. */
internal val BrandCyan = Color(0xFFDFF5F3)

private val Ink = Color(0xFF142033)
private val Paper = Color(0xFFF4F7FB)
private val Slate = Color(0xFF3D4D63)

/**
 * Light and dark schemes keep the tide primary and the soft cyan brand as a
 * container accent. Text, outlines, and status colors are roles with WCAG AA
 * contrast (4.5:1 for text, 3:1 for borders) on the surfaces they sit on.
 * [surfaceTint] is transparent so elevation does not wash content toward cyan.
 */
internal val AgentLightColors = lightColorScheme(
    primary = Tide,
    onPrimary = Color.White,
    primaryContainer = BrandCyan,
    onPrimaryContainer = Color(0xFF0C3D3A),
    inversePrimary = TideLight,
    secondary = Slate,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFE4EAF2),
    onSecondaryContainer = Ink,
    tertiary = Color(0xFF0E6B45),
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFD8F3E4),
    onTertiaryContainer = Color(0xFF084D30),
    background = Paper,
    onBackground = Ink,
    surface = Color.White,
    onSurface = Ink,
    surfaceVariant = Color(0xFFE1E8F0),
    onSurfaceVariant = Slate,
    surfaceTint = Color.Transparent,
    inverseSurface = Ink,
    inverseOnSurface = Color(0xFFE8EEF6),
    error = Color(0xFF9F1D1D),
    onError = Color.White,
    errorContainer = Color(0xFFF8D7D4),
    onErrorContainer = Color(0xFF6B1212),
    outline = Color(0xFF4B5563),
    outlineVariant = Color(0xFF5B6570),
    scrim = Ink,
    surfaceBright = Color.White,
    surfaceDim = Color(0xFFD5DEE8),
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color(0xFFF7FAFC),
    surfaceContainer = Color(0xFFEEF3F8),
    surfaceContainerHigh = Color(0xFFE6EDF5),
    surfaceContainerHighest = Color(0xFFDCE5F0),
)

internal val AgentDarkColors = darkColorScheme(
    primary = TideLight,
    onPrimary = Ink,
    primaryContainer = Color(0xFF163844),
    onPrimaryContainer = BrandCyan,
    inversePrimary = Tide,
    secondary = Color(0xFFB7C6D6),
    onSecondary = Ink,
    secondaryContainer = Color(0xFF243244),
    onSecondaryContainer = Color(0xFFE8EEF6),
    tertiary = Color(0xFF8EDEBB),
    onTertiary = Color(0xFF043322),
    tertiaryContainer = Color(0xFF0E3D2C),
    onTertiaryContainer = Color(0xFFC8F5DF),
    background = Color(0xFF101820),
    onBackground = Color(0xFFE8EEF6),
    surface = Color(0xFF182230),
    onSurface = Color(0xFFE8EEF6),
    surfaceVariant = Color(0xFF243244),
    onSurfaceVariant = Color(0xFFC5D4E4),
    surfaceTint = Color.Transparent,
    inverseSurface = Color(0xFFE8EEF6),
    inverseOnSurface = Ink,
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF8C1D18),
    onErrorContainer = Color(0xFFFFDAD6),
    outline = Color(0xFF8E99A4),
    outlineVariant = Color(0xFFAEB8C2),
    scrim = Color.Black,
    surfaceBright = Color(0xFF2C3C50),
    surfaceDim = Color(0xFF101820),
    surfaceContainerLowest = Color(0xFF0C141C),
    surfaceContainerLow = Color(0xFF15202C),
    surfaceContainer = Color(0xFF1C2A3A),
    surfaceContainerHigh = Color(0xFF243447),
    surfaceContainerHighest = Color(0xFF2E4054),
)

internal data class DisabledColors(val container: Color, val content: Color)

/** Opaque disabled colors. Alpha-on-surface ghosts fall under 3:1 and disappear on paper. */
internal fun agentDisabledColors(dark: Boolean): DisabledColors = if (dark) {
    DisabledColors(container = Color(0xFF314256), content = Color(0xFFD5E2EF))
} else {
    DisabledColors(container = Color(0xFFD5DEE8), content = Color(0xFF3D4D63))
}

internal fun contrastRatio(foreground: Color, background: Color): Float {
    val lighter = max(foreground.luminance(), background.luminance())
    val darker = min(foreground.luminance(), background.luminance())
    return (lighter + 0.05f) / (darker + 0.05f)
}

@Composable
internal fun agentDisabledColors(): DisabledColors {
    val dark = MaterialTheme.colorScheme.background.luminance() < 0.5f
    return agentDisabledColors(dark)
}

@Composable
fun AgentTheme(
    darkTheme: Boolean = androidx.compose.foundation.isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val scheme = if (darkTheme) AgentDarkColors else AgentLightColors
    MaterialTheme(colorScheme = scheme) {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = scheme.background,
            contentColor = scheme.onBackground,
        ) {
            content()
        }
    }
}
