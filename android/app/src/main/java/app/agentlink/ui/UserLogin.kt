package app.agentlink.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import app.agentlink.account.AccountApi
import app.agentlink.account.DEFAULT_RELAY
import app.agentlink.account.DeviceRow
import app.agentlink.account.NodeRow
import app.agentlink.account.SESSION_EXPIRED_MESSAGE
import app.agentlink.account.SessionMaintain
import app.agentlink.account.SessionStore
import app.agentlink.account.UserAccount
import app.agentlink.account.isAuthFailure
import app.agentlink.account.maintainSession
import app.agentlink.model.fingerprintProblem
import app.agentlink.model.relayProblem
import kotlin.coroutines.EmptyCoroutineContext
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
fun UserLogin(
    api: AccountApi,
    sessions: SessionStore,
    onConnected: (UserAccount) -> Unit,
    onActAsNode: (UserAccount) -> Unit,
    onAdmin: () -> Unit,
    background: CoroutineDispatcher = Dispatchers.IO,
    ui: CoroutineDispatcher = Dispatchers.Main.immediate,
    notice: String? = null,
    onPairPhone: (() -> Unit)? = null,
    showIntro: Boolean = true,
) {
    var server by remember { mutableStateOf(DEFAULT_RELAY) }
    var fingerprint by remember { mutableStateOf("") }
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var totp by remember { mutableStateOf("") }
    var account by remember { mutableStateOf<UserAccount?>(sessions.load()) }
    var nodes by remember { mutableStateOf<List<NodeRow>>(emptyList()) }
    var devices by remember { mutableStateOf<List<DeviceRow>>(emptyList()) }
    var status by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var askTotp by remember { mutableStateOf(false) }
    val totpFocus = remember { FocusRequester() }
    val totpNeeded = askTotp || totp.isNotEmpty()

    LaunchedEffect(account?.user, account?.deviceId) {
        val saved = account ?: return@LaunchedEffect
        when (val maintained = withContext(background) { maintainSession(saved, api) }) {
            is SessionMaintain.Ready -> {
                val current = maintained.account
                if (current != saved) {
                    val stored = runCatching { sessions.save(current) }
                    if (stored.isFailure) {
                        status = stored.exceptionOrNull()?.message ?: "couldn't save the session"
                        return@LaunchedEffect
                    }
                    account = current
                }
                val listed = withContext(background) { runCatching { api.listNodes(current) } }
                listed.onSuccess { nodes = it }.onFailure { error ->
                    if (isAuthFailure(error.message)) {
                        runCatching { sessions.clear() }
                        account = null
                        nodes = emptyList()
                        devices = emptyList()
                        status = SESSION_EXPIRED_MESSAGE
                    } else {
                        status = error.message ?: "node list failed"
                    }
                }
            }
            is SessionMaintain.SignedOut -> {
                runCatching { sessions.clear() }
                account = null
                nodes = emptyList()
                devices = emptyList()
                status = maintained.message
            }
            is SessionMaintain.Offline -> status = maintained.message
        }
    }

    if (account == null) {
        Column(
            modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (showIntro) {
                ScreenIntro(
                    "Sign in",
                    "Username and password. Enter the relay URL under the self-hosted relay section.",
                )
            } else {
                SupportingText("Username and password. Enter the relay URL under the self-hosted relay section.")
            }
            AgentField(
                username,
                { username = it },
                "Username",
                Modifier.fillMaxWidth().testTag("username"),
                supporting = "Account name.",
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None),
            )
            AgentField(
                password,
                { password = it },
                "Password",
                Modifier.fillMaxWidth().testTag("password"),
                visualTransformation = PasswordVisualTransformation(),
                supporting = "Password for that account.",
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            )
            if (totpNeeded) {
                AgentField(
                    totp,
                    { totp = it },
                    "Authenticator code",
                    Modifier.fillMaxWidth().testTag("totp").focusRequester(totpFocus),
                    supporting = "6-digit code from your authenticator.",
                    placeholder = "6-digit code",
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                )
                LaunchedEffect(Unit) { totpFocus.requestFocus() }
            }
            val banner = status.ifEmpty { notice.orEmpty() }
            if (banner.isNotEmpty()) {
                StatusLine(
                    banner,
                    problem = banner != "logged out" && banner != "enrolled as node",
                    modifier = Modifier.testTag("status"),
                )
            }
            PrimaryButton(
                onClick = {
                    val relayError = relayProblem(server)
                    val pinError = fingerprintProblem(fingerprint)
                    if (relayError != null || pinError != null) {
                        status = relayError ?: pinError.orEmpty()
                        return@PrimaryButton
                    }
                    busy = true
                    val serverNow = server.trim()
                    val fingerprintNow = fingerprint.trim()
                    val usernameNow = username.trim()
                    val passwordNow = password
                    val totpNow = totp.trim()
                    runOffMain(background) {
                        val result = runCatching {
                            api.login(serverNow, fingerprintNow, usernameNow, passwordNow, totpNow, "android")
                        }
                        val listed = result.map { api.listNodes(it) }
                        applyOnMain(ui) {
                            busy = false
                            result.onSuccess {
                                val stored = runCatching { sessions.save(it) }
                                if (stored.isFailure) {
                                    status = stored.exceptionOrNull()?.message ?: "couldn't save the session"
                                    return@onSuccess
                                }
                                account = it
                                status = ""
                                onConnected(it)
                            }.onFailure { error ->
                                val message = error.message ?: "login failed"
                                if (message.contains("totp", ignoreCase = true)) askTotp = true
                                status = loginHint(message)
                            }
                            listed.onSuccess { nodes = it }
                        }
                    }
                },
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().testTag("login"),
                text = if (busy) "Signing in" else "Sign in",
            )
            SelfHostedRelay(
                relay = server,
                onRelay = { server = it },
                fingerprint = fingerprint,
                onFingerprint = { fingerprint = it },
                relayModifier = Modifier.fillMaxWidth().testTag("server"),
                fingerprintModifier = Modifier.fillMaxWidth().testTag("fingerprint"),
            )
            QuietButton("Admin token", onAdmin, Modifier.fillMaxWidth())
            if (onPairPhone != null) {
                QuietButton("Pair this phone", onPairPhone, Modifier.fillMaxWidth())
            }
        }
    } else {
        val current = account!!
        Column(
            modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(current.user, style = MaterialTheme.typography.headlineMedium, modifier = Modifier.testTag("session-user"))
            if (status.isNotEmpty()) {
                StatusLine(
                    status,
                    problem = status != "logged out" && status != "enrolled as node",
                    modifier = Modifier.testTag("status"),
                )
            }
            Column(
                modifier = Modifier.testTag("nodes").semantics(mergeDescendants = true) {},
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (nodes.isEmpty()) {
                    Text("No machines yet", style = MaterialTheme.typography.bodyLarge)
                }
                nodes.forEach { node ->
                    AgentCard {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp),
                        ) {
                            Text(node.name, style = MaterialTheme.typography.titleMedium)
                            Text(
                                "${node.relation} ${node.access}",
                                fontFamily = FontFamily.Monospace,
                                style = MaterialTheme.typography.bodyLarge,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            ConnectionStatus(node.online)
                        }
                    }
                }
            }
            PrimaryButton(
                text = "Control machines",
                onClick = { onConnected(current) },
                modifier = Modifier.fillMaxWidth().testTag("open-machines"),
            )
            PrimaryButton(
                onClick = {
                    runOffMain(background) {
                        val result = runCatching { api.enrollAsNode(current, "phone") }
                        applyOnMain(ui) {
                            result.onSuccess {
                                status = "enrolled as node"
                                onActAsNode(current)
                            }.onFailure { status = it.message ?: "enroll failed" }
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth().testTag("act-node"),
                text = "Act as node",
            )
            SecondaryButton(
                onClick = {
                    runOffMain(background) {
                        val result = runCatching { api.listDevices(current) }
                        applyOnMain(ui) {
                            result.onSuccess { devices = it }.onFailure { status = it.message ?: "devices failed" }
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth().testTag("devices-button"),
                text = "Devices",
            )
            if (devices.isNotEmpty()) {
                Column(
                    modifier = Modifier.testTag("devices"),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    devices.forEach { device ->
                        AgentCard {
                            Row(
                                modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp).fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                RevokedMark(device.revoked)
                                Text(
                                    "${device.name} ${device.id} revoked=${device.revoked}",
                                    fontFamily = FontFamily.Monospace,
                                    style = MaterialTheme.typography.bodyLarge,
                                )
                            }
                        }
                    }
                }
            }
            SecondaryButton(
                onClick = {
                    runOffMain(background) {
                        runCatching { api.logout(current) }
                        applyOnMain(ui) {
                            runCatching { sessions.clear() }
                            account = null
                            nodes = emptyList()
                            devices = emptyList()
                            askTotp = false
                            totp = ""
                            status = "logged out"
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth().testTag("logout"),
                text = "Log out",
            )
        }
    }
}

private fun loginHint(message: String): String {
    val totp = message.contains("totp", ignoreCase = true)
    return when {
        totp && message.contains("invalid", ignoreCase = true) ->
            "That authenticator code was not accepted."
        totp -> "This account needs the 6-digit authenticator code."
        else -> message
    }
}

private fun runOffMain(background: CoroutineDispatcher, block: () -> Unit) {
    if (background.isDispatchNeeded(EmptyCoroutineContext)) {
        background.dispatch(EmptyCoroutineContext) { block() }
    } else {
        block()
    }
}

private fun applyOnMain(ui: CoroutineDispatcher, block: () -> Unit) {
    if (ui.isDispatchNeeded(EmptyCoroutineContext)) {
        ui.dispatch(EmptyCoroutineContext) { block() }
    } else {
        block()
    }
}
