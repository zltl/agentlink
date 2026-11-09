package app.agentlink.ui

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.heightIn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.ui.Alignment
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import app.agentlink.account.AccountApi
import app.agentlink.account.EncryptedSessionStore
import app.agentlink.account.EnrollLink
import app.agentlink.account.SessionMaintain
import app.agentlink.account.SessionStore
import app.agentlink.account.UserAccount
import app.agentlink.account.maintainSession
import app.agentlink.bridge.LinkBridge
import app.agentlink.model.ConsentChoices
import app.agentlink.model.ConsentStep
import app.agentlink.model.consentBody
import app.agentlink.model.consentSteps
import app.agentlink.model.decisionsComplete
import app.agentlink.node.SafStore
import app.agentlink.node.allFilesGranted
import app.agentlink.node.shizukuReady
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import rikka.shizuku.Shizuku

private enum class SessionGate { Checking, Ready }

@Composable
fun AgentApp(
    bridge: LinkBridge,
    account: AccountApi,
    enroll: EnrollLink? = null,
    store: SessionStore? = null,
) {
    val context = LocalContext.current
    val sessions = store ?: remember { EncryptedSessionStore(context) }
    var gate by remember { mutableStateOf(SessionGate.Checking) }
    var user by remember { mutableStateOf<UserAccount?>(null) }
    var notice by remember { mutableStateOf<String?>(null) }
    var startupError by remember { mutableStateOf<String?>(null) }
    var checkId by remember { mutableIntStateOf(0) }
    val gateEpoch = remember { AtomicInteger(0) }

    LaunchedEffect(checkId) {
        val ticket = gateEpoch.get()
        fun current(): Boolean = isActive && gateEpoch.get() == ticket
        val saved = withContext(Dispatchers.IO) { sessions.load() }
        if (!current()) return@LaunchedEffect
        if (saved == null) {
            gate = SessionGate.Ready
            return@LaunchedEffect
        }
        when (val outcome = withContext(Dispatchers.IO) { maintainSession(saved, account) }) {
            is SessionMaintain.Ready -> {
                if (!current()) return@LaunchedEffect
                if (outcome.account != saved) {
                    val stored = runCatching { sessions.save(outcome.account) }
                    if (stored.isFailure) {
                        if (!current()) return@LaunchedEffect
                        user = saved
                        startupError = stored.exceptionOrNull()?.message ?: "couldn't save the session"
                        gate = SessionGate.Ready
                        return@LaunchedEffect
                    }
                }
                if (!current()) return@LaunchedEffect
                user = outcome.account
                gate = SessionGate.Ready
            }
            is SessionMaintain.SignedOut -> {
                if (!current()) return@LaunchedEffect
                runCatching { sessions.clear() }
                user = null
                notice = outcome.message
                gate = SessionGate.Ready
            }
            is SessionMaintain.Offline -> {
                if (!current()) return@LaunchedEffect
                user = outcome.account
                startupError = outcome.message
                gate = SessionGate.Ready
            }
        }
    }

    if (gate == SessionGate.Checking) {
        CheckingSession(onSignInAgain = {
            gateEpoch.incrementAndGet()
            runCatching { sessions.clear() }
            user = null
            notice = null
            startupError = null
            gate = SessionGate.Ready
            checkId += 1
        })
    } else {
        val start = remember(gate) {
            when {
                enroll != null -> Routes.Setup
                user != null -> Routes.Machines
                else -> Routes.Login
            }
        }
        AppShell(
            bridge = bridge,
            account = account,
            sessions = sessions,
            enroll = enroll,
            user = user,
            onUser = { user = it },
            notice = notice,
            onNotice = { notice = it },
            startupError = startupError,
            startDestination = start,
        )
    }
}

@Composable
internal fun NodeWizard(
    step: ConsentStep,
    choices: ConsentChoices,
    onChoices: (ConsentChoices) -> Unit,
    onStep: (ConsentStep) -> Unit,
    onProjection: (Int, Intent) -> Unit,
    onStart: () -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    fun advance(next: ConsentChoices) {
        onChoices(next.copy(visited = next.visited + step))
        val order = consentSteps()
        val index = order.indexOf(step)
        onStep(order.getOrElse(index + 1) { ConsentStep.Review })
    }
    val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        advance(choices.copy(notifications = granted))
    }
    val folders = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri != null) {
            SafStore(context).remember(uri)
            advance(choices.copy(folders = true))
        }
    }
    val capture = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val data = result.data
        if (result.resultCode == Activity.RESULT_OK && data != null) {
            onProjection(result.resultCode, data)
            advance(choices.copy(screenCapture = true))
        }
    }
    when (step) {
        ConsentStep.Notifications -> ConsentPage(
            step,
            onAllow = {
                if (Build.VERSION.SDK_INT >= 33) {
                    notifications.launch(android.Manifest.permission.POST_NOTIFICATIONS)
                } else {
                    advance(choices.copy(notifications = true))
                }
            },
            onSkip = { advance(choices.copy(notifications = false)) },
        )
        ConsentStep.AppStorage -> ConsentPage(step, onAllow = { advance(choices.copy(appStorage = true)) }, onSkip = null)
        ConsentStep.Commands -> ConsentPage(
            step,
            onAllow = { advance(choices.copy(commands = true)) },
            onSkip = { advance(choices.copy(commands = false)) },
        )
        ConsentStep.Folders -> ConsentPage(
            step,
            onAllow = { folders.launch(null) },
            onSkip = { advance(choices.copy(folders = false)) },
        )
        ConsentStep.AllFiles -> AllFilesPage(
            onOpenSettings = {
                val intent = if (Build.VERSION.SDK_INT >= 30) {
                    Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:${context.packageName}"))
                } else {
                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${context.packageName}"))
                }
                context.startActivity(intent)
            },
            onAllow = { advance(choices.copy(allFiles = true)) },
            onSkip = { advance(choices.copy(allFiles = false)) },
        )
        ConsentStep.ScreenCapture -> ScreenPage(
            live = choices.liveStream,
            onLive = { onChoices(choices.copy(liveStream = it)) },
            onAllow = {
                val manager = context.getSystemService(android.media.projection.MediaProjectionManager::class.java)
                capture.launch(manager.createScreenCaptureIntent())
            },
            onSkip = { advance(choices.copy(screenCapture = false, liveStream = false)) },
        )
        ConsentStep.Accessibility -> ConsentPage(
            step,
            onAllow = {
                context.startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
                advance(choices.copy(accessibility = true))
            },
            onSkip = { advance(choices.copy(accessibility = false)) },
        )
        ConsentStep.Shizuku -> ConsentPage(
            step,
            onAllow = {
                if (shizukuReady().not()) {
                    try {
                        if (Shizuku.pingBinder()) Shizuku.requestPermission(41)
                    } catch (_: Throwable) {
                        // Shizuku is not installed. The flag still records the choice.
                    }
                }
                advance(choices.copy(shizuku = true))
            },
            onSkip = { advance(choices.copy(shizuku = false)) },
        )
        ConsentStep.Root -> ConsentPage(
            step,
            onAllow = { advance(choices.copy(root = true)) },
            onSkip = { advance(choices.copy(root = false)) },
        )
        ConsentStep.Review -> ReviewPage(
            choices = choices,
            canStart = decisionsComplete(choices),
            onStart = onStart,
            onBack = onBack,
        )
    }
}

@Composable
private fun AllFilesPage(onOpenSettings: () -> Unit, onAllow: () -> Unit, onSkip: () -> Unit) {
    var revision by remember { mutableIntStateOf(0) }
    val granted = revision >= 0 && allFilesGranted()
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(ConsentStep.AllFiles.title, style = MaterialTheme.typography.headlineMedium)
        SupportingText(consentBody(ConsentStep.AllFiles))
        ChoiceStatus(granted, if (granted) "All-files access is on." else "All-files access is off.")
        PrimaryButton("Open system settings", onOpenSettings, Modifier.fillMaxWidth())
        SecondaryButton("Check again", onClick = { revision++ }, modifier = Modifier.fillMaxWidth())
        PrimaryButton("Allow all files", onAllow, Modifier.fillMaxWidth(), enabled = granted)
        SecondaryButton("Skip", onSkip, Modifier.fillMaxWidth())
    }
}

@Composable
private fun ScreenPage(live: Boolean, onLive: (Boolean) -> Unit, onAllow: () -> Unit, onSkip: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(ConsentStep.ScreenCapture.title, style = MaterialTheme.typography.headlineMedium)
        SupportingText(consentBody(ConsentStep.ScreenCapture))
        Row(
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("Allow a future live stream flag", style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            AgentSwitch(checked = live, onCheckedChange = onLive)
        }
        SupportingText("This phone still serves screenshots. webrtc_signal answers that live video is unavailable.")
        PrimaryButton("Allow screen capture", onAllow, Modifier.fillMaxWidth())
        SecondaryButton("Skip", onSkip, Modifier.fillMaxWidth())
    }
}
