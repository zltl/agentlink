package app.agentlink.model

import org.json.JSONObject
import java.io.File

/** Raw node error when a caller is not an account session and owner keys are set. */
const val SIGNED_GRANT_MARKER = "signed grant required"

private const val GRANT_FIX_TIP_MARKER = "Controller public key:"
private val NODE_ID_PATTERN = Regex("^[0-9a-fA-F]{64}$")
private val CONTROLLER_KEY_IN_REJECTION =
    Regex("controller public key is ([0-9a-fA-F]{64})", RegexOption.IGNORE_CASE)

fun isSignedGrantFailure(message: String?): Boolean =
    message?.contains(SIGNED_GRANT_MARKER, ignoreCase = true) == true

/** True for the phone note produced by [decorateGrantFailure]. */
fun isGrantFixNote(message: String?): Boolean =
    message?.contains(GRANT_FIX_TIP_MARKER) == true

/**
 * Public key the node said it checked, when a newer node includes it.
 * Empty when the rejection only names the target node.
 */
fun controllerKeyFromRejection(message: String?): String =
    message?.let { CONTROLLER_KEY_IN_REJECTION.find(it)?.groupValues?.getOrNull(1) }
        .orEmpty()
        .lowercase()

/** Key a grant must name: the one the node checked, otherwise this phone's key. */
fun grantGrantee(message: String?, localKey: String?): String {
    val checked = controllerKeyFromRejection(message)
    if (checked.isNotEmpty()) return checked
    return localKey?.trim().orEmpty().lowercase()
}

fun grantIssueCommand(node: String, pubkey: String): String =
    "agentlink grant issue --node $node --grantee $pubkey --policy full --ttl 30d " +
        "--issuer-data-dir <node data dir> --out -"

fun grantFileName(node: String): String = "${node.trim().lowercase()}.json"

/**
 * Explain a signed-grant rejection using this phone's controller key.
 *
 * Account login can list machines while a node that still requires a signed
 * grant refuses the control session. The grant has to be for the key that
 * session signs with. The phone's own node service is a different identity
 * and is not that key. [localKey] is this device's Ed25519 public key. A
 * rejection that already names a controller key uses that key for the
 * command, because that is the grantee the node checked.
 */
fun decorateGrantFailure(
    message: String,
    node: String,
    localKey: String?,
    identityDir: String? = null,
): String {
    if (message.contains(GRANT_FIX_TIP_MARKER)) return message
    val local = localKey?.trim().orEmpty().lowercase()
    val checked = controllerKeyFromRejection(message)
    val grantee = grantGrantee(message, local)
    val command = if (grantee.isNotEmpty()) {
        grantIssueCommand(node, grantee)
    } else {
        "agentlink grant issue --node $node --grantee <this phone's controller public key> " +
            "--policy full --ttl 30d --issuer-data-dir <node data dir> --out -"
    }
    return buildString {
        append("This machine still requires a signed grant for this phone's control session on $node. ")
        append("Signing in lists machines; it does not replace that signature. ")
        append("The phone's own node service is not this controller key.\n")
        append("$GRANT_FIX_TIP_MARKER ")
        if (grantee.isNotEmpty()) append(grantee) else append("still reading this phone's key")
        append('\n')
        if (checked.isNotEmpty() && local.isNotEmpty() && checked != local) {
            append("The machine checked $checked. This phone's key is $local. ")
            append("Issue the grant for the key the machine checked.\n")
        }
        append("On the node host, with that machine's issuer, run:\n$command\n")
        append("Import the JSON it prints. The node still checks the signature.")
        if (!identityDir.isNullOrBlank() && grantee.isNotEmpty()) {
            append("\nIt is saved as ${File(identityDir, "grants/${grantFileName(node)}").absolutePath}.")
        }
    }
}

/**
 * Store a pasted grant where the client loads `grants/<node_id>.json`.
 *
 * The node verifies the signature against its owner keys. This only rejects
 * a paste bound to another node or another controller key.
 */
fun importGrantJson(
    identityDir: File,
    expectedNode: String,
    expectedGrantee: String,
    json: String,
): Result<File> = runCatching {
    val text = json.trim()
    require(text.isNotEmpty()) { "Paste the grant JSON first." }
    val grant = try {
        JSONObject(text)
    } catch (_: Exception) {
        throw IllegalArgumentException("That is not valid JSON. Paste the whole grant object.")
    }
    val node = grant.optString("node_id").trim()
    require(node.isNotEmpty()) {
        "This JSON has no node_id. Paste the grant JSON, not the CLI summary."
    }
    val expected = expectedNode.trim()
    require(NODE_ID_PATTERN.matches(expected)) {
        "Node id $expected is not a 64-character public id; open the node from the machine list."
    }
    require(node.equals(expected, ignoreCase = true)) {
        "That grant is for node $node, not $expected."
    }
    val grantee = grant.optString("grantee_id").trim()
    require(grantee.isNotEmpty()) {
        "This JSON has no grantee_id. Paste the grant JSON, not the CLI summary."
    }
    val thisDevice = expectedGrantee.trim()
    if (thisDevice.isNotEmpty()) {
        require(grantee.equals(thisDevice, ignoreCase = true)) {
            "That grant is for device $grantee, not this controller. Issue it with this phone's key."
        }
    }
    require(grant.optString("sig_hex").isNotBlank()) {
        "This JSON is not a signed grant (no sig_hex). Paste the grant, not the CLI summary."
    }
    val dir = File(identityDir, "grants").apply { mkdirs() }
    val target = File(dir, grantFileName(node))
    val tmp = File(dir, "${target.name}.tmp")
    tmp.writeText(text + "\n")
    if (!tmp.renameTo(target)) {
        target.writeText(text + "\n")
        tmp.delete()
    }
    target
}
