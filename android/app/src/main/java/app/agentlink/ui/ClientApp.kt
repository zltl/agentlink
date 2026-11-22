package app.agentlink.ui

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import app.agentlink.account.DEFAULT_RELAY
import app.agentlink.account.looksLikeSessionExpiry
import app.agentlink.bridge.ClientSession
import app.agentlink.bridge.LinkBridge
import app.agentlink.bridge.MachineRow
import app.agentlink.bridge.PtySession
import app.agentlink.model.fingerprintProblem
import app.agentlink.model.relayProblem
import app.agentlink.node.ClientStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread

class ClientViewModel(private val bridge: LinkBridge, context: Context) : ViewModel() {
    private val store = ClientStore(context.applicationContext)
    private val identityDir = context.applicationContext.filesDir.absolutePath
    var relay by mutableStateOf(store.relay())
    var token by mutableStateOf(store.token())
    var fingerprint by mutableStateOf(store.fingerprint())
    var machines by mutableStateOf<List<MachineRow>>(emptyList())
    var pinWarnings by mutableStateOf<List<String>>(emptyList())
    var error by mutableStateOf<String?>(null)
    var busy by mutableStateOf(false)
    var refreshing by mutableStateOf(false)
    var loadedOnce by mutableStateOf(false)
    var sessionExpired by mutableStateOf<String?>(null)
    private var sessionEpoch = 0
    private val retainedPtys = ConcurrentHashMap<String, PtySession>()
    var session: ClientSession? = null
        private set

    fun retainedPty(machineId: String): PtySession? = retainedPtys[machineId]

    fun retainPty(machineId: String, pty: PtySession) {
        val previous = retainedPtys.put(machineId, pty)
        if (previous != null && previous !== pty) {
            closePtyAsync(previous)
        }
    }

    fun releasePty(machineId: String, expected: PtySession? = null) {
        val removed = if (expected == null) {
            retainedPtys.remove(machineId)
        } else if (retainedPtys.remove(machineId, expected)) {
            expected
        } else {
            null
        }
        if (removed != null) {
            closePtyAsync(removed)
        }
    }

    fun updateAccessToken(newToken: String) {
        val current = session ?: return
        current.updateAccessToken(newToken)
        sessionExpired = null
    }

    fun connect(onReady: () -> Unit) {
        val relayProblem = relayProblem(relay)
        val pinProblem = fingerprintProblem(fingerprint)
        if (relayProblem != null || pinProblem != null || token.isBlank()) {
            error = relayProblem ?: pinProblem ?: "Admin token is required"
            return
        }
        viewModelScope.launch {
            busy = true
            error = null
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    bridge.connect(relay.trim(), token.trim(), fingerprint.trim(), identityDir)
                }
            }
            busy = false
            result.onSuccess {
                openSession(it)
                store.save(relay.trim(), token.trim(), fingerprint.trim())
                refresh(onReady)
            }.onFailure { error = it.message }
        }
    }

    fun adopt(connected: ClientSession, onReady: () -> Unit = {}) {
        openSession(connected)
        error = null
        refresh(onReady)
    }

    fun disconnect() {
        sessionEpoch += 1
        closeAllPtysAsync()
        val old = session
        session = null
        if (old != null) closeSessionAsync(old)
        machines = emptyList()
        pinWarnings = emptyList()
        error = null
        busy = false
        refreshing = false
        loadedOnce = false
        sessionExpired = null
    }

    fun refresh(onReady: () -> Unit = {}) {
        val epoch = sessionEpoch
        val current = session
        if (current == null) {
            busy = false
            refreshing = false
            if (loadedOnce) error = "Not connected to the relay."
            return
        }
        viewModelScope.launch {
            if (machines.isEmpty()) busy = true else refreshing = true
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val listed = current.listMachines()
                    val warnings = runCatching { current.nodePinWarnings() }.getOrDefault(emptyList())
                    listed to warnings
                }
            }
            if (epoch != sessionEpoch) return@launch
            busy = false
            refreshing = false
            loadedOnce = true
            result.onSuccess { (listed, warnings) ->
                machines = listed
                pinWarnings = warnings
                error = null
                onReady()
            }.onFailure {
                val message = it.message ?: "Couldn't refresh machines."
                error = message
                noteSessionExpiry(message)
            }
        }
    }

    private fun openSession(connected: ClientSession) {
        sessionEpoch += 1
        sessionExpired = null
        closeAllPtysAsync()
        val old = session
        session = connected
        if (old != null && old !== connected) {
            closeSessionAsync(old)
        }
    }

    private fun closeAllPtysAsync() {
        val keys = retainedPtys.keys.toList()
        val closing = keys.mapNotNull { retainedPtys.remove(it) }
        if (closing.isNotEmpty()) {
            thread(name = "agentlink-pty-close", isDaemon = true) {
                closing.forEach { runCatching { it.close() } }
            }
        }
    }

    private fun closePtyAsync(pty: PtySession) {
        thread(name = "agentlink-pty-close", isDaemon = true) {
            runCatching { pty.close() }
        }
    }

    private fun closeSessionAsync(old: ClientSession) {
        thread(name = "agentlink-client-close", isDaemon = true) {
            runCatching { old.close() }
        }
    }

    fun refreshIfConnected() {
        if (session == null) return
        refresh()
    }

    fun <T> work(block: (ClientSession) -> T, onDone: (Result<T>) -> Unit) {
        val current = session
        if (current == null) {
            onDone(Result.failure(IllegalStateException("Not connected to the relay.")))
            return
        }
        val epoch = sessionEpoch
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) { runCatching { block(current) } }
            if (epoch == sessionEpoch) noteSessionExpiry(result.exceptionOrNull()?.message)
            onDone(result)
        }
    }

    private fun noteSessionExpiry(message: String?) {
        if (sessionExpired == null && looksLikeSessionExpiry(message)) sessionExpired = message
    }

    override fun onCleared() {
        closeAllPtysAsync()
        val old = session
        session = null
        if (old != null) closeSessionAsync(old)
    }
}

class ClientViewModelFactory(private val bridge: LinkBridge, private val context: Context) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        return ClientViewModel(bridge, context.applicationContext) as T
    }
}

@Composable
fun ClientLogin(model: ClientViewModel, onConnected: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        ScreenIntro(
            "Admin token",
            "Legacy automation login. An everyday account uses username and password.",
        )
        AgentField(
            model.token,
            { model.token = it },
            "Admin token",
            Modifier.fillMaxWidth(),
            supporting = "From the relay data directory. Not your account password.",
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None),
        )
        SelfHostedRelay(
            relay = model.relay,
            onRelay = { model.relay = it },
            fingerprint = model.fingerprint,
            onFingerprint = { model.fingerprint = it },
            startOpen = model.relay.isBlank() || model.fingerprint.isNotBlank() || model.relay.trim() != DEFAULT_RELAY,
        )
        model.error?.let { ErrorNote(it) }
        PrimaryButton(
            text = if (model.busy) "Connecting" else "Connect",
            onClick = { model.connect(onConnected) },
            enabled = !model.busy,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
fun clientModel(bridge: LinkBridge): ClientViewModel {
    val context = LocalContext.current
    return viewModel(factory = ClientViewModelFactory(bridge, context))
}
