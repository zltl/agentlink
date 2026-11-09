package app.agentlink.ui

import android.content.ClipboardManager
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import app.agentlink.model.grantFileName
import app.agentlink.model.grantIssueCommand
import app.agentlink.model.importGrantJson
import java.io.File

/**
 * Shows this phone's controller public key, the owner command that signs a
 * grant for that key, and a field to import the printed JSON.
 *
 * Import writes `<filesDir>/grants/<node_id>.json`. The client reads that
 * file on the next request. The node still verifies the signature.
 */
@Composable
internal fun GrantFixDialog(
    node: String,
    pubkey: String?,
    identityDir: File,
    onClose: () -> Unit,
    onImported: (File) -> Unit,
) {
    val context = LocalContext.current
    val key = pubkey?.trim().orEmpty()
    var pasted by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val command = if (key.isNotEmpty()) {
        grantIssueCommand(node, key)
    } else {
        "agentlink grant issue --node $node --grantee <this phone's controller public key> --policy full " +
            "--ttl 30d --issuer-data-dir <node data dir> --out -"
    }
    val clipboard = context.getSystemService(ClipboardManager::class.java)
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("Grant for this controller") },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    "This machine still requires a signed grant for the controller key below. " +
                        "On the node host, sign it with that machine's issuer, then paste the JSON. " +
                        "The node checks the signature. This phone's node service is a different key.",
                    style = MaterialTheme.typography.bodyLarge,
                )
                SectionLabel("Controller public key")
                Text(
                    key.ifEmpty { "Reading this phone's controller key…" },
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
                TextButton(
                    onClick = { copyPlainText(context, "Controller public key", key) },
                    enabled = key.isNotEmpty(),
                ) { Text("Copy controller key") }
                SectionLabel("On the node host")
                Text(
                    command,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
                TextButton(
                    onClick = { copyPlainText(context, "Grant command", command) },
                    enabled = key.isNotEmpty(),
                ) { Text("Copy command") }
                AgentField(
                    pasted,
                    { pasted = it; error = null },
                    "Grant JSON",
                    Modifier.fillMaxWidth(),
                    singleLine = false,
                    supporting = "Paste the JSON printed by --out -. It is saved as grants/${grantFileName(node)}.",
                )
                TextButton(onClick = {
                    val text = clipboard?.primaryClip
                        ?.takeIf { it.itemCount > 0 }
                        ?.getItemAt(0)
                        ?.coerceToText(context)
                        ?.toString()
                    if (!text.isNullOrBlank()) {
                        pasted = text
                        error = null
                    }
                }) { Text("Paste from clipboard") }
                error?.let { ErrorNote(it) }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                if (key.isEmpty()) {
                    error = "This phone's controller key is not ready yet."
                    return@TextButton
                }
                importGrantJson(identityDir, node, key, pasted)
                    .onSuccess {
                        error = null
                        onImported(it)
                    }
                    .onFailure {
                        error = it.message ?: "Couldn't import that grant."
                    }
            }) { Text("Import grant") }
        },
        dismissButton = {
            TextButton(onClick = onClose) { Text("Cancel") }
        },
    )
}
