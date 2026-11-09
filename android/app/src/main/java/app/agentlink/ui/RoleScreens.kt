package app.agentlink.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import app.agentlink.account.DEFAULT_RELAY
import app.agentlink.model.ConsentChoices
import app.agentlink.model.ConsentStep
import app.agentlink.model.ceilingSummary
import app.agentlink.model.consentBody

@Composable
fun RoleScreen(onNode: () -> Unit, onClient: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            BrandMark()
            Text("agentlink", style = MaterialTheme.typography.headlineLarge)
        }
        SupportingText("This phone can be a node that dials your relay, or a client that controls machines already paired.")
        PrimaryButton("This phone", onNode, Modifier.fillMaxWidth())
        SupportingText("Pair it as a node. It connects outbound, keeps a notification up, and reconnects.")
        PrimaryButton("Control a machine", onClient, Modifier.fillMaxWidth())
        SupportingText("List machines, edit files, run a shell, transfer with the fast path, read the audit log, and view the screen.")
    }
}

@Composable
fun ConsentPage(
    step: ConsentStep,
    onAllow: () -> Unit,
    onSkip: (() -> Unit)?,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(step.title, style = MaterialTheme.typography.headlineMedium)
        SupportingText(consentBody(step))
        PrimaryButton(
            text = if (step == ConsentStep.AppStorage) "Allow app storage" else "Allow",
            onClick = onAllow,
            modifier = Modifier.fillMaxWidth(),
        )
        if (onSkip != null) {
            SecondaryButton("Skip", onSkip, Modifier.fillMaxWidth())
        }
    }
}

@Composable
fun ReviewPage(choices: ConsentChoices, canStart: Boolean, onStart: () -> Unit, onBack: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Review", style = MaterialTheme.typography.headlineMedium)
        SupportingText(consentBody(ConsentStep.Review))
        AgentCard {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                ceilingSummary(choices).forEach { line ->
                    Text(line, style = MaterialTheme.typography.bodyLarge)
                }
            }
        }
        PrimaryButton("Start node", onStart, Modifier.fillMaxWidth(), enabled = canStart)
        SecondaryButton("Back", onBack, Modifier.fillMaxWidth())
    }
}

@Composable
fun NodeStatusPage(status: String, nodeId: String, audit: String, onStop: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Node", style = MaterialTheme.typography.headlineMedium)
        AgentCard {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                StatusLine(status, problem = looksLikeProblem(status))
                if (nodeId.isNotBlank()) {
                    Text(nodeId, style = MaterialTheme.typography.bodyLarge, fontFamily = FontFamily.Monospace)
                }
            }
        }
        Text("Audit", style = MaterialTheme.typography.titleMedium)
        AgentCard {
            Text(
                audit.ifBlank { "No audit lines yet." },
                modifier = Modifier.padding(16.dp),
                style = MaterialTheme.typography.bodyLarge,
                fontFamily = FontFamily.Monospace,
                color = if (audit.isBlank()) {
                    MaterialTheme.colorScheme.onSurfaceVariant
                } else {
                    MaterialTheme.colorScheme.onSurface
                },
            )
        }
        SecondaryButton("Stop node", onStop, Modifier.fillMaxWidth())
    }
}

@Composable
fun SetupFields(
    relay: String,
    fingerprint: String,
    token: String,
    name: String,
    onRelay: (String) -> Unit,
    onFingerprint: (String) -> Unit,
    onToken: (String) -> Unit,
    onName: (String) -> Unit,
    onContinue: () -> Unit,
    problem: String?,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Pair this phone", style = MaterialTheme.typography.headlineMedium)
        SupportingText("Paste the enrollment token. Enter the relay URL; nothing is selected for you.")
        AgentField(
            token,
            onToken,
            "Pairing token",
            Modifier.fillMaxWidth(),
            supporting = "From the install command or the phone QR code.",
            placeholder = "Optional if this phone is already enrolled",
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None),
        )
        AgentField(
            name,
            onName,
            "Name",
            Modifier.fillMaxWidth(),
            supporting = "Optional. Blank uses this phone's model name.",
            placeholder = "Optional",
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Words),
        )
        SelfHostedRelay(
            relay = relay,
            onRelay = onRelay,
            fingerprint = fingerprint,
            onFingerprint = onFingerprint,
            startOpen = fingerprint.isNotBlank() || relay.trim() != DEFAULT_RELAY,
        )
        if (problem != null) ErrorNote(problem)
        AgentDivider()
        PrimaryButton("Review permissions", onContinue, Modifier.fillMaxWidth())
        Spacer(Modifier.height(8.dp))
    }
}

@Composable
fun MachineList(names: List<String>, onOpen: (Int) -> Unit, onRefresh: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text("Machines", style = MaterialTheme.typography.headlineMedium)
            SecondaryButton("Refresh", onRefresh)
        }
        if (names.isEmpty()) Text("No paired machines.", style = MaterialTheme.typography.bodyLarge)
        names.forEachIndexed { index, name ->
            AgentCard(onClick = { onOpen(index) }) {
                Text(
                    name,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                    style = MaterialTheme.typography.bodyLarge,
                )
            }
        }
    }
}
