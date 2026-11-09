package app.agentlink.ui

import androidx.compose.material3.ColorScheme
import androidx.compose.ui.graphics.Color
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ContrastTokenTest {
    @Test
    fun lightTokensKeepBrandAndReadableRoles() {
        assertEquals(Color(0xFF1F4E79), AgentLightColors.primary)
        assertEquals(BrandCyan, AgentLightColors.primaryContainer)
        assertEquals(Color.Transparent, AgentLightColors.surfaceTint)
        assertScheme(AgentLightColors)
        val disabled = agentDisabledColors(dark = false)
        assertText("light disabled content", disabled.content, disabled.container)
        assertUi("light disabled border", AgentLightColors.outline, disabled.container)
    }

    @Test
    fun darkTokensKeepBrandAndReadableRoles() {
        assertEquals(Color(0xFF9EC1DE), AgentDarkColors.primary)
        assertEquals(BrandCyan, AgentDarkColors.onPrimaryContainer)
        assertEquals(Color.Transparent, AgentDarkColors.surfaceTint)
        assertScheme(AgentDarkColors)
        val disabled = agentDisabledColors(dark = true)
        assertText("dark disabled content", disabled.content, disabled.container)
        assertUi("dark disabled border", AgentDarkColors.outline, disabled.container)
    }

    private fun assertScheme(scheme: ColorScheme) {
        assertText("onSurface/surface", scheme.onSurface, scheme.surface)
        assertText("onSurface/background", scheme.onSurface, scheme.background)
        assertText("onSurface/primaryContainer", scheme.onSurface, scheme.primaryContainer)
        assertText("onSurface/surfaceContainerHigh", scheme.onSurface, scheme.surfaceContainerHigh)
        assertText("onBackground/background", scheme.onBackground, scheme.background)
        assertText("onSurfaceVariant/surface", scheme.onSurfaceVariant, scheme.surface)
        assertText("onSurfaceVariant/background", scheme.onSurfaceVariant, scheme.background)
        assertText("onSurfaceVariant/surfaceVariant", scheme.onSurfaceVariant, scheme.surfaceVariant)
        assertText("onSurfaceVariant/primaryContainer", scheme.onSurfaceVariant, scheme.primaryContainer)
        assertText("onPrimary/primary", scheme.onPrimary, scheme.primary)
        assertText("onPrimaryContainer/primaryContainer", scheme.onPrimaryContainer, scheme.primaryContainer)
        assertText("onSecondary/secondary", scheme.onSecondary, scheme.secondary)
        assertText("onSecondaryContainer/secondaryContainer", scheme.onSecondaryContainer, scheme.secondaryContainer)
        assertText("onTertiary/tertiary", scheme.onTertiary, scheme.tertiary)
        assertText("onTertiaryContainer/tertiaryContainer", scheme.onTertiaryContainer, scheme.tertiaryContainer)
        assertText("onError/error", scheme.onError, scheme.error)
        assertText("onErrorContainer/errorContainer", scheme.onErrorContainer, scheme.errorContainer)
        assertText("error/surface", scheme.error, scheme.surface)
        assertText("error/background", scheme.error, scheme.background)
        assertText("primary/background label", scheme.primary, scheme.background)
        assertText("primary/primaryContainer label", scheme.primary, scheme.primaryContainer)
        assertUi("outline/surface", scheme.outline, scheme.surface)
        assertUi("outline/background", scheme.outline, scheme.background)
        assertUi("outline/primaryContainer", scheme.outline, scheme.primaryContainer)
        assertUi("outlineVariant/surface", scheme.outlineVariant, scheme.surface)
        assertUi("outlineVariant/background", scheme.outlineVariant, scheme.background)
        assertUi("tertiary/background", scheme.tertiary, scheme.background)
        assertUi("tertiary/tertiaryContainer", scheme.tertiary, scheme.tertiaryContainer)
    }

    private fun assertText(name: String, foreground: Color, background: Color) {
        val ratio = contrastRatio(foreground, background)
        assertTrue("$name contrast $ratio is below 4.5", ratio >= 4.5f)
    }

    private fun assertUi(name: String, foreground: Color, background: Color) {
        val ratio = contrastRatio(foreground, background)
        assertTrue("$name contrast $ratio is below 3", ratio >= 3f)
    }
}
