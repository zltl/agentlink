package app.agentlink.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.CloudDone
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.TextButton
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import app.agentlink.R
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import app.agentlink.account.DEFAULT_RELAY

private val FieldShape = RoundedCornerShape(12.dp)
private val CardShape = RoundedCornerShape(12.dp)

@Composable
fun AgentField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String?,
    modifier: Modifier = Modifier,
    visualTransformation: VisualTransformation = VisualTransformation.None,
    singleLine: Boolean = true,
    enabled: Boolean = true,
    supporting: String? = null,
    placeholder: String? = null,
    keyboardOptions: KeyboardOptions = KeyboardOptions.Default,
) {
    val scheme = MaterialTheme.colorScheme
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        enabled = enabled,
        modifier = modifier.heightIn(min = 56.dp),
        label = label?.let { title -> { Text(title) } },
        placeholder = placeholder?.let { hint -> { Text(hint) } },
        supportingText = supporting?.let { line -> { Text(line) } },
        singleLine = singleLine,
        visualTransformation = visualTransformation,
        keyboardOptions = keyboardOptions,
        textStyle = MaterialTheme.typography.bodyLarge,
        shape = FieldShape,
        colors = OutlinedTextFieldDefaults.colors(
            focusedTextColor = scheme.onSurface,
            unfocusedTextColor = scheme.onSurface,
            disabledTextColor = scheme.onSurfaceVariant,
            errorTextColor = scheme.onSurface,
            focusedContainerColor = scheme.primaryContainer,
            unfocusedContainerColor = scheme.surface,
            disabledContainerColor = scheme.surfaceVariant,
            errorContainerColor = scheme.surface,
            cursorColor = scheme.primary,
            errorCursorColor = scheme.error,
            focusedBorderColor = scheme.primary,
            unfocusedBorderColor = scheme.outline,
            disabledBorderColor = scheme.outline,
            errorBorderColor = scheme.error,
            focusedLabelColor = scheme.primary,
            unfocusedLabelColor = scheme.onSurfaceVariant,
            disabledLabelColor = scheme.onSurfaceVariant,
            errorLabelColor = scheme.error,
            focusedPlaceholderColor = scheme.onSurfaceVariant,
            unfocusedPlaceholderColor = scheme.onSurfaceVariant,
            disabledPlaceholderColor = scheme.onSurfaceVariant,
            errorPlaceholderColor = scheme.onSurfaceVariant,
        ),
    )
}

@Composable
fun PrimaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val scheme = MaterialTheme.colorScheme
    val disabled = agentDisabledColors()
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.heightIn(min = 48.dp),
        shape = CardShape,
        border = if (enabled) null else BorderStroke(1.dp, scheme.outline),
        colors = ButtonDefaults.buttonColors(
            containerColor = scheme.primary,
            contentColor = scheme.onPrimary,
            disabledContainerColor = disabled.container,
            disabledContentColor = disabled.content,
        ),
    ) {
        Text(text)
    }
}

@Composable
fun SecondaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val scheme = MaterialTheme.colorScheme
    val disabled = agentDisabledColors()
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.heightIn(min = 48.dp),
        shape = CardShape,
        border = BorderStroke(1.dp, if (enabled) scheme.outline else scheme.outlineVariant),
        colors = ButtonDefaults.outlinedButtonColors(
            contentColor = scheme.primary,
            disabledContentColor = disabled.content,
            disabledContainerColor = Color.Transparent,
        ),
    ) {
        Text(text)
    }
}

@Composable
fun QuietButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    TextButton(
        onClick = onClick,
        modifier = modifier.heightIn(min = 48.dp),
        colors = ButtonDefaults.textButtonColors(
            contentColor = MaterialTheme.colorScheme.primary,
        ),
    ) {
        Text(text)
    }
}

/**
 * Relay URL and certificate pin for a self-hosted relay.
 * Relay URL and certificate pin. Empty means unset; it does not select a host.
 */
@Composable
fun SelfHostedRelay(
    relay: String,
    onRelay: (String) -> Unit,
    fingerprint: String,
    onFingerprint: (String) -> Unit,
    relayModifier: Modifier = Modifier.fillMaxWidth(),
    fingerprintModifier: Modifier = Modifier.fillMaxWidth(),
    startOpen: Boolean = relay.isBlank(),
) {
    var open by rememberSaveable { mutableStateOf(startOpen) }
    val custom = fingerprint.isNotBlank() || relay.trim() != DEFAULT_RELAY
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        QuietButton(
            text = if (open) "Hide self-hosted relay" else "Self-hosted relay",
            onClick = { open = !open },
            modifier = Modifier.fillMaxWidth().testTag("advanced-relay"),
        )
        if (!open && custom) {
            SupportingText("A custom relay or certificate pin is still in use.")
        }
        if (open) {
            SupportingText("Enter the relay URL. There is no built-in relay.")
            AgentField(
                relay,
                onRelay,
                "Relay URL",
                relayModifier,
                supporting = "WebSocket address, for example wss://relay.example:7443.",
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.None,
                    keyboardType = KeyboardType.Uri,
                ),
            )
            AgentField(
                fingerprint,
                onFingerprint,
                "Certificate pin",
                fingerprintModifier,
                supporting = "Optional. Empty trusts the system certificate. Node ids are pinned on this phone after the first list.",
                placeholder = "Optional",
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None),
            )
        }
    }
}

@Composable
fun AgentCard(
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    val colors = androidx.compose.material3.CardDefaults.outlinedCardColors(
        containerColor = MaterialTheme.colorScheme.surface,
        contentColor = MaterialTheme.colorScheme.onSurface,
    )
    val border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant)
    if (onClick != null) {
        OutlinedCard(
            onClick = onClick,
            modifier = modifier.fillMaxWidth().heightIn(min = 48.dp),
            shape = CardShape,
            colors = colors,
            border = border,
            content = content,
        )
    } else {
        OutlinedCard(
            modifier = modifier.fillMaxWidth(),
            shape = CardShape,
            colors = colors,
            border = border,
            content = content,
        )
    }
}

@Composable
fun SupportingText(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        modifier = modifier,
        style = MaterialTheme.typography.bodyLarge,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
fun AgentDivider(modifier: Modifier = Modifier) {
    HorizontalDivider(
        modifier = modifier,
        thickness = 1.dp,
        color = MaterialTheme.colorScheme.outlineVariant,
    )
}

enum class BannerTone { Error, Info }

@Composable
fun AgentBanner(
    text: String,
    tone: BannerTone,
    modifier: Modifier = Modifier,
    action: String? = null,
    onAction: (() -> Unit)? = null,
) {
    val scheme = MaterialTheme.colorScheme
    val container = if (tone == BannerTone.Error) scheme.errorContainer else scheme.secondaryContainer
    val content = if (tone == BannerTone.Error) scheme.onErrorContainer else scheme.onSecondaryContainer
    val border = if (tone == BannerTone.Error) scheme.error else scheme.outline
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = CardShape,
        color = container,
        contentColor = content,
        border = BorderStroke(1.dp, border),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(
                imageVector = if (tone == BannerTone.Error) Icons.Filled.Error else Icons.Filled.Info,
                contentDescription = null,
                modifier = Modifier.size(22.dp),
            )
            Text(text, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyLarge)
            if (action != null && onAction != null) {
                TextButton(
                    onClick = onAction,
                    colors = ButtonDefaults.textButtonColors(contentColor = content),
                ) {
                    Text(action)
                }
            }
        }
    }
}

@Composable
fun ErrorNote(text: String, modifier: Modifier = Modifier) {
    val scheme = MaterialTheme.colorScheme
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = CardShape,
        color = scheme.errorContainer,
        contentColor = scheme.onErrorContainer,
        border = BorderStroke(1.dp, scheme.error),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(horizontal = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(Icons.Filled.Error, contentDescription = null, modifier = Modifier.size(22.dp))
            Text(text, style = MaterialTheme.typography.bodyLarge)
        }
    }
}

@Composable
fun StatusLine(text: String, problem: Boolean, modifier: Modifier = Modifier) {
    if (!problem) {
        Text(
            text = text,
            modifier = modifier,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
        )
        return
    }
    val scheme = MaterialTheme.colorScheme
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = CardShape,
        color = scheme.errorContainer,
        contentColor = scheme.onErrorContainer,
        border = BorderStroke(1.dp, scheme.error),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(horizontal = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(Icons.Filled.Error, contentDescription = null, modifier = Modifier.size(22.dp))
            Text(text, modifier = modifier, style = MaterialTheme.typography.bodyLarge)
        }
    }
}

fun looksLikeProblem(text: String): Boolean {
    val value = text.lowercase()
    return value.contains("fail") ||
        value.contains("error") ||
        value.contains("unable") ||
        value.contains("invalid") ||
        value.contains("denied") ||
        value.contains("could not") ||
        value.contains("exception")
}

@Composable
fun ConnectionStatus(online: Boolean, modifier: Modifier = Modifier) {
    val scheme = MaterialTheme.colorScheme
    val container = if (online) scheme.tertiaryContainer else scheme.surfaceVariant
    val content = if (online) scheme.onTertiaryContainer else scheme.onSurfaceVariant
    val border = if (online) scheme.tertiary else scheme.outline
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(8.dp),
        color = container,
        contentColor = content,
        border = BorderStroke(1.dp, border),
    ) {
        Row(
            modifier = Modifier.heightIn(min = 32.dp).padding(horizontal = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Icon(
                imageVector = if (online) Icons.Filled.CloudDone else Icons.Filled.CloudOff,
                contentDescription = null,
                modifier = Modifier.size(18.dp),
            )
            Text(if (online) "Online" else "Offline", style = MaterialTheme.typography.labelLarge)
        }
    }
}

@Composable
fun ChoiceStatus(active: Boolean, text: String, modifier: Modifier = Modifier) {
    val scheme = MaterialTheme.colorScheme
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = CardShape,
        color = if (active) scheme.tertiaryContainer else scheme.surfaceVariant,
        contentColor = if (active) scheme.onTertiaryContainer else scheme.onSurfaceVariant,
        border = BorderStroke(1.dp, if (active) scheme.tertiary else scheme.outline),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(horizontal = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(
                imageVector = if (active) Icons.Filled.Check else Icons.Filled.Close,
                contentDescription = null,
                modifier = Modifier.size(22.dp),
            )
            Text(text, style = MaterialTheme.typography.bodyLarge)
        }
    }
}

@Composable
fun RevokedMark(revoked: Boolean, modifier: Modifier = Modifier) {
    Icon(
        imageVector = if (revoked) Icons.Filled.Error else Icons.Filled.Check,
        contentDescription = null,
        tint = if (revoked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.tertiary,
        modifier = modifier.size(22.dp),
    )
}

@Composable
fun BrandMark(modifier: Modifier = Modifier, size: Dp = 40.dp) {
    Surface(
        modifier = modifier.size(size),
        shape = CircleShape,
        color = MaterialTheme.colorScheme.primaryContainer,
        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
    ) {
        Image(
            painter = painterResource(R.mipmap.ic_launcher_foreground),
            contentDescription = null,
            modifier = Modifier.fillMaxSize().padding(2.dp),
            contentScale = ContentScale.Fit,
        )
    }
}

@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        modifier = modifier,
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.onSurface,
    )
}

@Composable
fun AgentSwitch(
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    val scheme = MaterialTheme.colorScheme
    Switch(
        checked = checked,
        onCheckedChange = onCheckedChange,
        modifier = modifier,
        colors = SwitchDefaults.colors(
            checkedThumbColor = scheme.onPrimary,
            checkedTrackColor = scheme.primary,
            checkedBorderColor = scheme.primary,
            uncheckedThumbColor = scheme.surface,
            uncheckedTrackColor = scheme.outline,
            uncheckedBorderColor = scheme.outline,
        ),
    )
}

@Composable
fun AgentFilterChip(
    selected: Boolean,
    label: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val scheme = MaterialTheme.colorScheme
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(label) },
        modifier = modifier,
        leadingIcon = if (selected) {
            {
                Icon(
                    Icons.Filled.Check,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                )
            }
        } else {
            null
        },
        shape = RoundedCornerShape(8.dp),
        colors = FilterChipDefaults.filterChipColors(
            containerColor = scheme.surface,
            labelColor = scheme.onSurface,
            iconColor = scheme.onSurfaceVariant,
            selectedContainerColor = scheme.primaryContainer,
            selectedLabelColor = scheme.onPrimaryContainer,
            selectedLeadingIconColor = scheme.onPrimaryContainer,
        ),
        border = FilterChipDefaults.filterChipBorder(
            enabled = true,
            selected = selected,
            borderColor = scheme.outline,
            selectedBorderColor = scheme.primary,
            disabledBorderColor = scheme.outlineVariant,
            disabledSelectedBorderColor = scheme.outline,
            borderWidth = 1.dp,
            selectedBorderWidth = 1.5.dp,
        ),
    )
}

@Composable
fun ScreenIntro(title: String, body: String? = null) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        BrandMark()
        Text(title, style = MaterialTheme.typography.headlineMedium)
    }
    if (body != null) SupportingText(body)
}
