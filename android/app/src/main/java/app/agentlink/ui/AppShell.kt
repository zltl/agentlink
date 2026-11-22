@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package app.agentlink.ui

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import app.agentlink.account.ACCESS_REFRESH_SKEW_SECONDS
import app.agentlink.account.AccountApi
import app.agentlink.account.DEFAULT_RELAY
import app.agentlink.account.DeviceRow
import app.agentlink.account.EnrollLink
import app.agentlink.account.SESSION_EXPIRED_MESSAGE
import app.agentlink.account.SESSION_OFFLINE_MESSAGE
import app.agentlink.account.SessionMaintain
import app.agentlink.account.SessionStore
import app.agentlink.account.UserAccount
import app.agentlink.account.isAuthFailure
import app.agentlink.account.maintainSession
import app.agentlink.account.newerStoredSession
import app.agentlink.account.sessionNowUnix
import app.agentlink.bridge.GrantRow
import app.agentlink.bridge.LinkBridge
import app.agentlink.bridge.MachineRow
import app.agentlink.bridge.NodePinRow
import app.agentlink.model.ConsentChoices
import app.agentlink.model.ConsentStep
import app.agentlink.model.consentSteps
import app.agentlink.model.resolveJoin
import app.agentlink.node.ConsentStore
import app.agentlink.node.NodeForegroundService
import app.agentlink.node.NodeRuntime
import app.agentlink.node.NodeSetup
import app.agentlink.node.SafStore
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

internal object Routes {
    const val Login = "login"
    const val Admin = "admin"
    const val Machines = "machines"
    const val Settings = "settings"
    const val Phone = "phone"
    const val Setup = "phone/setup"
    const val Consent = "phone/consent"
    const val Running = "phone/running"
    const val Machine = "machine/{id}"
    const val MachinePane = "machine/{id}/{pane}"
    const val Pair = "pair"

    fun machine(id: String) = "machine/${Uri.encode(id)}"

    fun machinePane(id: String, pane: String) = "machine/${Uri.encode(id)}/$pane"
}

private fun runOnMain(block: () -> Unit) {
    val main = Looper.getMainLooper()
    if (Looper.myLooper() == main) block() else Handler(main).post(block)
}

internal enum class ShellTab(val route: String, val label: String) {
    Machines(Routes.Machines, "Machines"),
    Phone(Routes.Phone, "This phone"),
    Settings(Routes.Settings, "Settings"),
}

private fun isShellRoot(route: String): Boolean {
    return route == Routes.Login || route == Routes.Machines || route == Routes.Phone || route == Routes.Settings
}

@Composable
internal fun CheckingSession(onSignInAgain: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
        ScreenIntro(
            "Checking session",
            "Refreshing your sign-in before opening machines.",
        )
        SecondaryButton(
            "Sign in again",
            onSignInAgain,
            Modifier.fillMaxWidth().testTag("sign-in-again"),
        )
    }
}

@Composable
internal fun AppShell(
    bridge: LinkBridge,
    account: AccountApi,
    sessions: SessionStore,
    enroll: EnrollLink?,
    user: UserAccount?,
    onUser: (UserAccount?) -> Unit,
    notice: String?,
    onNotice: (String?) -> Unit,
    startupError: String?,
    startDestination: String,
) {
    val context = LocalContext.current
    val nav = rememberNavController()
    val client = clientModel(bridge)
    val scope = rememberCoroutineScope()
    val epoch = remember { AtomicInteger(0) }
    var linkedToken by remember { mutableStateOf<String?>(null) }
    var linkedAccountKey by remember { mutableStateOf<Triple<String, String, String>?>(null) }
    val savedNode = remember { runCatching { ConsentStore(context).load() }.getOrNull() }
    val defaultPhoneName = remember { Build.MODEL?.takeIf { it.isNotBlank() } ?: "phone" }
    var relay by rememberSaveable {
        mutableStateOf(enroll?.server ?: user?.server ?: savedNode?.relay ?: DEFAULT_RELAY)
    }
    var fingerprint by rememberSaveable {
        mutableStateOf(enroll?.fingerprint ?: user?.fingerprint ?: savedNode?.fingerprint ?: "")
    }
    var token by rememberSaveable { mutableStateOf(enroll?.token ?: "") }
    var name by rememberSaveable { mutableStateOf(enroll?.name ?: savedNode?.name ?: "") }
    var choices by remember { mutableStateOf(savedNode?.choices ?: ConsentChoices()) }
    var step by remember { mutableStateOf(ConsentStep.Notifications) }
    var projection by remember { mutableStateOf<Intent?>(null) }
    var projectionCode by remember { mutableIntStateOf(0) }
    var settingsNote by remember { mutableStateOf("") }
    var hubGrantNode by remember { mutableStateOf<String?>(null) }
    var hubDeviceKey by remember { mutableStateOf<String?>(null) }
    val initialEnroll = remember { enroll?.token }
    val entry by nav.currentBackStackEntryAsState()
    val route = entry?.destination?.route ?: startDestination
    val machineId = entry?.arguments?.getString("id")?.let(Uri::decode)
    val machineName = client.machines.firstOrNull { it.id == machineId }?.name
    val title = when {
        route == Routes.Login -> "Sign in"
        route == Routes.Admin -> "Admin token"
        route == Routes.Machines -> "Machines"
        route == Routes.Machine -> machineName ?: "Machine"
        route == Routes.MachinePane -> paneTitle(entry?.arguments?.getString("pane"))
        route == Routes.Pair -> "Pair a machine"
        route == Routes.Settings -> "Settings"
        route == Routes.Phone -> "This phone"
        route == Routes.Setup -> "Pair this phone"
        route == Routes.Consent -> "Permissions"
        route == Routes.Running -> "Node"
        else -> "agentlink"
    }
    val root = isShellRoot(route)
    val tab = ShellTab.entries.firstOrNull { it.route == route }

    fun signOut(message: String, ending: UserAccount? = user) {
        if (message == SESSION_EXPIRED_MESSAGE && ending != null) {
            val kept = newerStoredSession(ending, runCatching { sessions.load() }.getOrNull())
            if (kept != null) {
                onUser(kept)
                client.error = null
                return
            }
        }
        epoch.incrementAndGet()
        linkedToken = null
        linkedAccountKey = null
        onUser(null)
        runCatching { sessions.clear() }
        client.disconnect()
        onNotice(message)
        runOnMain {
            nav.navigate(Routes.Login) {
                popUpTo(nav.graph.id) { inclusive = true }
                launchSingleTop = true
            }
        }
        if (ending != null) {
            scope.launch(Dispatchers.IO) { runCatching { account.logout(ending) } }
        }
    }

    fun applyOutcome(outcome: SessionMaintain) {
        when (outcome) {
            is SessionMaintain.Ready -> {
                if (outcome.account != user) {
                    val stored = runCatching { sessions.save(outcome.account) }
                    if (stored.isFailure) {
                        client.error = stored.exceptionOrNull()?.message ?: "couldn't save the session"
                        return
                    }
                    onUser(outcome.account)
                }
            }
            is SessionMaintain.SignedOut -> signOut(outcome.message)
            is SessionMaintain.Offline -> client.error = outcome.message
        }
    }

    fun recoverOrSignOut(current: UserAccount?) {
        val started = epoch.get()
        if (current == null) {
            signOut(SESSION_EXPIRED_MESSAGE)
            return
        }
        scope.launch {
            val outcome = withContext(Dispatchers.IO) {
                maintainSession(current.copy(accessExpiresUnix = 0), account)
            }
            if (!isActive || epoch.get() != started) return@launch
            when (outcome) {
                is SessionMaintain.Ready -> {
                    if (outcome.account.accessToken == current.accessToken &&
                        outcome.account.refreshToken == current.refreshToken
                    ) {
                        signOut(SESSION_EXPIRED_MESSAGE, outcome.account)
                    } else {
                        applyOutcome(outcome)
                    }
                }
                is SessionMaintain.SignedOut -> signOut(outcome.message, current)
                is SessionMaintain.Offline -> client.error = outcome.message
            }
        }
    }

    fun leaveSetup() {
        if (!nav.popBackStack()) {
            val dest = if (user != null) Routes.Phone else Routes.Login
            nav.navigate(dest) {
                popUpTo(Routes.Setup) { inclusive = true }
                launchSingleTop = true
            }
        }
    }

    fun leaveRunning() {
        if (!nav.popBackStack()) {
            val dest = if (user != null) Routes.Phone else Routes.Login
            nav.navigate(dest) {
                popUpTo(Routes.Running) { inclusive = true }
                launchSingleTop = true
            }
        }
    }

    fun stepBackConsent() {
        val order = consentSteps()
        val index = order.indexOf(step)
        if (index <= 0) {
            if (!nav.popBackStack()) leaveSetup()
        } else {
            step = order[index - 1]
        }
    }

    fun goBack() {
        when (nav.currentDestination?.route) {
            Routes.Consent -> stepBackConsent()
            Routes.Setup -> leaveSetup()
            Routes.Running -> leaveRunning()
            else -> nav.popBackStack()
        }
    }

    fun openTab(target: String) {
        val anchor = listOf(Routes.Machines, Routes.Phone, Routes.Settings).firstOrNull { candidate ->
            nav.currentBackStack.value.any { it.destination.route == candidate }
        }
        nav.navigate(target) {
            if (anchor != null) popUpTo(anchor) { saveState = true }
            launchSingleTop = true
            restoreState = true
        }
    }

    LaunchedEffect(startupError) {
        if (!startupError.isNullOrBlank()) client.error = startupError
    }

    LaunchedEffect(client.sessionExpired) {
        if (client.sessionExpired == null) return@LaunchedEffect
        val current = user
        client.sessionExpired = null
        recoverOrSignOut(current)
    }

    LaunchedEffect(enroll?.token) {
        val link = enroll ?: return@LaunchedEffect
        relay = link.server
        fingerprint = link.fingerprint
        token = link.token
        name = link.name
        if (link.token != initialEnroll) {
            nav.navigate(Routes.Setup) { launchSingleTop = true }
        }
    }

    LaunchedEffect(user?.accessToken) {
        val started = epoch.get()
        val current = user ?: return@LaunchedEffect
        if (current.accessToken.isNotBlank() && current.accessToken == linkedToken) return@LaunchedEffect
        val accountKey = Triple(current.server.trim(), current.fingerprint.trim(), current.deviceId)
        // If we already hold a live ClientSession for this account, rotate the
        // access token in-place so active PTY and Desktop sessions stay alive.
        if (client.session != null && linkedAccountKey == accountKey) {
            val updated = withContext(Dispatchers.IO) {
                runCatching { client.updateAccessToken(current.accessToken) }
            }
            if (!isActive || epoch.get() != started) return@LaunchedEffect
            if (updated.isSuccess) {
                linkedToken = current.accessToken
                if (client.error != null || client.machines.isEmpty()) {
                    client.refresh()
                }
                return@LaunchedEffect
            }
        }
        val opened = withContext(Dispatchers.IO) { runCatching { account.connect(current) } }
        if (!isActive || epoch.get() != started) return@LaunchedEffect
        if (opened.isSuccess) {
            linkedToken = current.accessToken
            linkedAccountKey = accountKey
            client.adopt(opened.getOrThrow())
            return@LaunchedEffect
        }
        val failure = opened.exceptionOrNull()
        if (!isAuthFailure(failure?.message)) {
            client.error = failure?.message ?: "Couldn't open the session."
            return@LaunchedEffect
        }
        val outcome = withContext(Dispatchers.IO) {
            maintainSession(current.copy(accessExpiresUnix = 0), account)
        }
        if (!isActive || epoch.get() != started) return@LaunchedEffect
        when (outcome) {
            is SessionMaintain.Ready -> {
                if (outcome.account.refreshToken != current.refreshToken ||
                    outcome.account.accessToken != current.accessToken
                ) {
                    val stored = runCatching { sessions.save(outcome.account) }
                    if (stored.isFailure) {
                        client.error = stored.exceptionOrNull()?.message ?: "couldn't save the session"
                        return@LaunchedEffect
                    }
                }
                val second = withContext(Dispatchers.IO) { runCatching { account.connect(outcome.account) } }
                if (!isActive || epoch.get() != started) return@LaunchedEffect
                if (second.isSuccess) {
                    linkedToken = outcome.account.accessToken
                    linkedAccountKey = Triple(
                        outcome.account.server.trim(),
                        outcome.account.fingerprint.trim(),
                        outcome.account.deviceId,
                    )
                    onUser(outcome.account)
                    client.adopt(second.getOrThrow())
                } else if (isAuthFailure(second.exceptionOrNull()?.message)) {
                    signOut(SESSION_EXPIRED_MESSAGE, outcome.account)
                } else {
                    linkedToken = outcome.account.accessToken
                    onUser(outcome.account)
                    client.error = second.exceptionOrNull()?.message ?: SESSION_OFFLINE_MESSAGE
                }
            }
            is SessionMaintain.SignedOut -> signOut(outcome.message)
            is SessionMaintain.Offline -> client.error = outcome.message
        }
    }

    LaunchedEffect(user?.accessToken, user?.accessExpiresUnix) {
        val started = epoch.get()
        val current = user ?: return@LaunchedEffect
        val waitSeconds = current.accessExpiresUnix - ACCESS_REFRESH_SKEW_SECONDS - sessionNowUnix()
        if (waitSeconds > 0) delay(waitSeconds.coerceAtMost(86_400L) * 1000)
        if (!isActive || epoch.get() != started) return@LaunchedEffect
        val latest = user ?: return@LaunchedEffect
        if (latest.accessToken != current.accessToken) return@LaunchedEffect
        val outcome = withContext(Dispatchers.IO) {
            maintainSession(latest, account, nowUnix = latest.accessExpiresUnix)
        }
        if (!isActive || epoch.get() != started) return@LaunchedEffect
        if (outcome is SessionMaintain.Ready && outcome.account == latest) return@LaunchedEffect
        applyOutcome(outcome)
    }

    val lifecycle = LocalLifecycleOwner.current.lifecycle
    LaunchedEffect(lifecycle, user?.refreshToken) {
        val started = epoch.get()
        lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            val latest = user ?: return@repeatOnLifecycle
            val outcome = withContext(Dispatchers.IO) { maintainSession(latest, account) }
            if (!isActive || epoch.get() != started) return@repeatOnLifecycle
            if (outcome is SessionMaintain.Ready && outcome.account == latest) return@repeatOnLifecycle
            applyOutcome(outcome)
        }
    }

    BackHandler(enabled = !root) { goBack() }

    val showRefresh = route == Routes.Machines || route == Routes.Machine
    AgentScaffold(
        title = title,
        showBack = !root,
        onBack = ::goBack,
        tab = tab,
        onTab = { openTab(it.route) },
        actions = {
            if (showRefresh) {
                IconButton(onClick = { client.refresh() }, modifier = Modifier.testTag("refresh-machines")) {
                    Icon(Icons.Filled.Refresh, contentDescription = "Refresh")
                }
            }
        },
    ) { padding ->
        NavHost(
            navController = nav,
            startDestination = startDestination,
            modifier = Modifier.padding(padding).fillMaxSize(),
        ) {
            composable(Routes.Login) {
                UserLogin(
                    api = account,
                    sessions = sessions,
                    onConnected = { signedIn ->
                        onNotice(null)
                        onUser(signedIn)
                        nav.navigate(Routes.Machines) {
                            popUpTo(Routes.Login) { inclusive = true }
                            launchSingleTop = true
                        }
                    },
                    onActAsNode = { signedIn ->
                        relay = signedIn.server
                        fingerprint = signedIn.fingerprint
                        token = ""
                        name = "phone"
                        nav.navigate(Routes.Setup)
                    },
                    onAdmin = { nav.navigate(Routes.Admin) },
                    notice = notice,
                    onPairPhone = { nav.navigate(Routes.Setup) },
                    showIntro = false,
                )
            }
            composable(Routes.Admin) {
                ClientLogin(
                    client,
                    onConnected = {
                        nav.navigate(Routes.Machines) {
                            popUpTo(nav.graph.findStartDestination().id) { inclusive = true }
                            launchSingleTop = true
                        }
                    },
                )
            }
            composable(Routes.Machines) {
                ClientHome(
                    client,
                    onOpen = { machine ->
                        nav.navigate(Routes.machine(machine.id)) { launchSingleTop = true }
                    },
                    onPair = { nav.navigate(Routes.Pair) },
                    showHeader = false,
                )
            }
            composable(Routes.Pair) {
                PairMachineScreen(client)
            }
            composable(
                route = Routes.Machine,
                arguments = listOf(navArgument("id") { type = NavType.StringType }),
            ) { destination ->
                val id = Uri.decode(destination.arguments?.getString("id").orEmpty())
                MachineRoute(client, id, onBack = { nav.popBackStack() }) { machine ->
                    MachineHub(
                        machine = machine,
                        error = client.error,
                        refreshing = client.refreshing,
                        onRefresh = { client.refresh() },
                        onOpen = { action ->
                            nav.navigate(Routes.machinePane(machine.id, action.pane))
                        },
                        onManageGrant = {
                            hubGrantNode = machine.id
                            scope.launch {
                                hubDeviceKey = withContext(Dispatchers.IO) {
                                    runCatching { account.devicePublicHex() }.getOrNull()
                                }?.takeIf { it.isNotBlank() }
                            }
                        },
                    )
                    if (hubGrantNode == machine.id) {
                        GrantFixDialog(
                            node = machine.id,
                            pubkey = hubDeviceKey,
                            identityDir = context.filesDir,
                            onClose = { hubGrantNode = null },
                            onImported = {
                                hubGrantNode = null
                                client.refresh()
                            },
                        )
                    }
                }
            }
            composable(
                route = Routes.MachinePane,
                arguments = listOf(
                    navArgument("id") { type = NavType.StringType },
                    navArgument("pane") { type = NavType.StringType },
                ),
            ) { destination ->
                val id = Uri.decode(destination.arguments?.getString("id").orEmpty())
                val pane = destination.arguments?.getString("pane").orEmpty()
                MachineRoute(client, id, onBack = { nav.popBackStack() }) { machine ->
                    when (pane) {
                        MachineAction.Files.pane -> FilesPane(client, machine, account)
                        MachineAction.Terminal.pane -> TerminalPane(client, machine, account)
                        MachineAction.Desktop.pane -> DesktopPane(client, machine, account)
                        MachineAction.Transfer.pane -> TransferPane(client, machine, account)
                        MachineAction.Audit.pane -> AuditPane(client, machine, account)
                        else -> MissingMachine(onBack = { nav.popBackStack() })
                    }
                }
            }
            composable(Routes.Settings) {
                SettingsPage(
                    user = user,
                    api = account,
                    client = client,
                    note = settingsNote,
                    onActAsNode = {
                        val current = user
                        if (current == null) {
                            nav.navigate(Routes.Setup)
                        } else {
                            scope.launch {
                                val result = withContext(Dispatchers.IO) {
                                    runCatching { account.enrollAsNode(current, defaultPhoneName) }
                                }
                                result.onSuccess {
                                    relay = current.server
                                    fingerprint = current.fingerprint
                                    token = ""
                                    name = defaultPhoneName
                                    runOnMain { nav.navigate(Routes.Setup) }
                                }.onFailure { error ->
                                    if (isAuthFailure(error.message)) recoverOrSignOut(current)
                                    else settingsNote = error.message ?: "enroll failed"
                                }
                            }
                        }
                    },
                    onAdmin = { nav.navigate(Routes.Admin) },
                    onLogout = { signOut("logged out") },
                    onAuthFailure = { recoverOrSignOut(user) },
                )
            }
            composable(Routes.Phone) {
                PhonePage(
                    onPair = { nav.navigate(Routes.Setup) },
                    onQuickStart = {
                        NodeForegroundService.start(context)
                        nav.navigate(Routes.Running) { launchSingleTop = true }
                    },
                    onOpenRunning = { nav.navigate(Routes.Running) { launchSingleTop = true } },
                    onStop = { NodeForegroundService.stop(context) },
                )
            }
            composable(Routes.Setup) {
                val problem = resolveJoin(relay, fingerprint, token, name).exceptionOrNull()?.message
                SetupFields(
                    relay, fingerprint, token, name,
                    { relay = it }, { fingerprint = it }, { token = it }, { name = it },
                    onContinue = {
                        val resolved = resolveJoin(relay, fingerprint, token, name).getOrNull()
                            ?: return@SetupFields
                        relay = resolved.relay
                        fingerprint = resolved.fingerprint
                        token = resolved.token
                        name = resolved.name
                        val prior = runCatching { ConsentStore(context).load()?.choices }.getOrNull()
                        if (prior != null && choices.visited.isEmpty()) {
                            choices = prior
                        }
                        step = ConsentStep.Notifications
                        nav.navigate(Routes.Consent)
                    },
                    problem = problem,
                )
            }
            composable(Routes.Consent) {
                NodeWizard(
                    step = step,
                    choices = choices,
                    onChoices = { choices = it },
                    onStep = { step = it },
                    onProjection = { code, intent ->
                        projectionCode = code
                        projection = intent
                    },
                    onStart = {
                        ConsentStore(context).save(
                            NodeSetup(relay.trim(), fingerprint.trim(), token.trim(), name.trim(), choices),
                        )
                        NodeForegroundService.start(context, projectionCode, projection)
                        nav.navigate(Routes.Running) {
                            popUpTo(Routes.Setup) { inclusive = true }
                            launchSingleTop = true
                        }
                    },
                    onBack = { stepBackConsent() },
                )
            }
            composable(Routes.Running) {
                val status by NodeRuntime.status.collectAsState()
                val nodeId by NodeRuntime.nodeId.collectAsState()
                NodeStatusPage(status, nodeId, NodeRuntime.tail(40), onStop = {
                    NodeForegroundService.stop(context)
                    leaveRunning()
                })
            }
        }
    }
}

@Composable
private fun MachineRoute(
    client: ClientViewModel,
    id: String,
    onBack: () -> Unit,
    content: @Composable (MachineRow) -> Unit,
) {
    val machine = client.machines.firstOrNull { it.id == id }
    LaunchedEffect(id) { client.refreshIfConnected() }
    if (machine == null) MissingMachine(onBack) else content(machine)
}

@Composable
internal fun AgentScaffold(
    title: String,
    showBack: Boolean,
    onBack: () -> Unit,
    tab: ShellTab?,
    onTab: (ShellTab) -> Unit,
    actions: @Composable RowScope.() -> Unit = {},
    content: @Composable (androidx.compose.foundation.layout.PaddingValues) -> Unit,
) {
    val scheme = MaterialTheme.colorScheme
    Scaffold(
        containerColor = scheme.background,
        contentColor = scheme.onBackground,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            TopAppBar(
                windowInsets = WindowInsets(0, 0, 0, 0),
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = scheme.surface,
                    titleContentColor = scheme.onSurface,
                    navigationIconContentColor = scheme.onSurface,
                ),
                navigationIcon = {
                    if (showBack) {
                        IconButton(onClick = onBack, modifier = Modifier.testTag("top-back")) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                        }
                    }
                },
                title = { Text(title, modifier = Modifier.testTag("top-title")) },
                actions = actions,
            )
        },
        bottomBar = {
            if (tab != null) {
                NavigationBar(
                    containerColor = scheme.surface,
                    contentColor = scheme.onSurface,
                    windowInsets = WindowInsets(0, 0, 0, 0),
                ) {
                    ShellTab.entries.forEach { item ->
                        NavigationBarItem(
                            modifier = Modifier.testTag("nav-${item.name.lowercase()}"),
                            selected = tab == item,
                            onClick = { onTab(item) },
                            alwaysShowLabel = true,
                            icon = {
                                Icon(
                                    when (item) {
                                        ShellTab.Machines -> Icons.Filled.Devices
                                        ShellTab.Phone -> Icons.Filled.PhoneAndroid
                                        ShellTab.Settings -> Icons.Filled.Settings
                                    },
                                    contentDescription = null,
                                )
                            },
                            label = { Text(item.label) },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = scheme.onPrimaryContainer,
                                selectedTextColor = scheme.onSurface,
                                indicatorColor = scheme.primaryContainer,
                                unselectedIconColor = scheme.onSurfaceVariant,
                                unselectedTextColor = scheme.onSurfaceVariant,
                            ),
                        )
                    }
                }
            }
        },
        content = content,
    )
}

@Composable
private fun PhonePage(
    onPair: () -> Unit,
    onQuickStart: () -> Unit,
    onOpenRunning: () -> Unit,
    onStop: () -> Unit,
) {
    val context = LocalContext.current
    val running by NodeRuntime.running.collectAsState()
    val status by NodeRuntime.status.collectAsState()
    val savedSetup = remember(running) { runCatching { ConsentStore(context).load() }.getOrNull() }
    val safStore = remember { SafStore(context) }
    var safRoots by remember { mutableStateOf(runCatching { safStore.roots() }.getOrDefault(emptyList())) }
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SupportingText("Pair it as a node. It dials out, keeps a notification up, and reconnects on its own.")
        AgentCard {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    if (running) "Node is running" else "Not running on this phone",
                    style = MaterialTheme.typography.titleMedium,
                )
                if (running) {
                    StatusLine(status, problem = looksLikeProblem(status))
                } else if (savedSetup != null && savedSetup.choices.appStorage) {
                    SupportingText("Saved setup ready for ${savedSetup.relay}.")
                } else {
                    SupportingText("Pair this phone when another machine should be able to reach it.")
                }
            }
        }
        if (!running && savedSetup != null && savedSetup.choices.appStorage) {
            PrimaryButton(
                "Start with saved setup",
                onQuickStart,
                Modifier.fillMaxWidth().testTag("quick-start-phone"),
            )
            SecondaryButton("Edit setup & permissions", onPair, Modifier.fillMaxWidth().testTag("pair-phone"))
        } else {
            PrimaryButton("Pair this phone", onPair, Modifier.fillMaxWidth().testTag("pair-phone"))
        }
        if (running) {
            SecondaryButton("Node status & audit", onOpenRunning, Modifier.fillMaxWidth().testTag("open-node-status"))
            SecondaryButton("Stop node", onStop, Modifier.fillMaxWidth())
        }
        if (safRoots.isNotEmpty()) {
            SectionLabel("Granted folders")
            safRoots.forEach { (id, uri) ->
                AgentCard {
                    Row(
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp).fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text("saf:/$id", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleMedium)
                            SupportingText(uri)
                        }
                        TextButton(onClick = {
                            safStore.removeRoot(id)
                            safRoots = safStore.roots()
                        }) {
                            Text("Revoke")
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SettingsPage(
    user: UserAccount?,
    api: AccountApi,
    client: ClientViewModel,
    note: String,
    onActAsNode: () -> Unit,
    onAdmin: () -> Unit,
    onLogout: () -> Unit,
    onAuthFailure: (String) -> Unit,
) {
    val context = LocalContext.current
    var devices by remember { mutableStateOf<List<DeviceRow>>(emptyList()) }
    var pins by remember { mutableStateOf<List<NodePinRow>>(emptyList()) }
    var grants by remember { mutableStateOf<List<GrantRow>>(emptyList()) }
    var pubkey by remember { mutableStateOf("") }
    var showImportGrant by remember { mutableStateOf(false) }
    var grantJsonDraft by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    LaunchedEffect(note) { if (note.isNotEmpty()) status = note }
    LaunchedEffect(api) {
        pubkey = withContext(Dispatchers.IO) { runCatching { api.devicePublicHex() }.getOrDefault("") }
    }
    fun loadPins() {
        scope.launch {
            val res = withContext(Dispatchers.IO) {
                runCatching {
                    client.session?.listNodePins()
                        ?: user?.let { api.listNodePins(it) }
                        ?: emptyList()
                }
            }
            res.onSuccess {
                pins = it
                if (it.isEmpty()) status = "No node pins saved yet."
            }.onFailure { status = it.message ?: "Couldn't load node pins." }
        }
    }
    fun loadGrants() {
        scope.launch {
            val res = withContext(Dispatchers.IO) {
                runCatching {
                    client.session?.listGrants()
                        ?: user?.let { api.listGrants(it) }
                        ?: emptyList()
                }
            }
            res.onSuccess {
                grants = it
                if (it.isEmpty()) status = "No signed grants stored."
            }.onFailure { status = it.message ?: "Couldn't load signed grants." }
        }
    }
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (user == null) {
            SupportingText("Signed in with an admin token.")
            PrimaryButton("Pair this phone", onActAsNode, Modifier.fillMaxWidth())
        } else {
            AgentCard {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(
                        user.user,
                        style = MaterialTheme.typography.headlineSmall,
                        modifier = Modifier.testTag("settings-user"),
                    )
                    SupportingText(user.server)
                }
            }
            if (pubkey.isNotBlank()) {
                AgentCard {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        SectionLabel("Controller public key")
                        Text(pubkey, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                        TextButton(onClick = {
                            copyPlainText(context, "Controller public key", pubkey)
                            status = "Copied controller public key."
                        }) {
                            Text("Copy key")
                        }
                    }
                }
            }
            SectionLabel("Account")
            SecondaryButton(
                text = "Devices",
                onClick = {
                    scope.launch {
                        val result = withContext(Dispatchers.IO) { runCatching { api.listDevices(user) } }
                        result.onSuccess { devices = it }.onFailure { error ->
                            if (isAuthFailure(error.message)) onAuthFailure(SESSION_EXPIRED_MESSAGE)
                            else status = error.message ?: "devices failed"
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth().testTag("devices-button"),
            )
            if (devices.isNotEmpty()) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.testTag("devices")) {
                    devices.forEach { device ->
                        AgentCard {
                            Row(
                                modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp).fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                RevokedMark(device.revoked)
                                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                    Text(device.name, style = MaterialTheme.typography.titleMedium)
                                    Text(
                                        device.id,
                                        fontFamily = FontFamily.Monospace,
                                        style = MaterialTheme.typography.bodyLarge,
                                    )
                                    Text(
                                        if (device.revoked) "Revoked" else "Active",
                                        style = MaterialTheme.typography.bodyLarge,
                                        color = if (device.revoked) {
                                            MaterialTheme.colorScheme.error
                                        } else {
                                            MaterialTheme.colorScheme.tertiary
                                        },
                                    )
                                }
                                if (!device.revoked) {
                                    TextButton(onClick = {
                                        scope.launch {
                                            val res = withContext(Dispatchers.IO) {
                                                runCatching { api.revokeDevice(user, device.id) }
                                            }
                                            res.onSuccess {
                                                status = "Revoked ${device.name}."
                                                devices = devices.map {
                                                    if (it.id == device.id) it.copy(revoked = true) else it
                                                }
                                            }.onFailure { err ->
                                                if (isAuthFailure(err.message)) onAuthFailure(SESSION_EXPIRED_MESSAGE)
                                                else status = err.message ?: "Couldn't revoke device."
                                            }
                                        }
                                    }) {
                                        Text("Revoke")
                                    }
                                }
                            }
                        }
                    }
                }
            }
            PrimaryButton("Act as node", onActAsNode, Modifier.fillMaxWidth().testTag("act-node"))
        }
        SectionLabel("Security")
        SecondaryButton("Node pins", onClick = { loadPins() }, modifier = Modifier.fillMaxWidth().testTag("node-pins-button"))
        if (pins.isNotEmpty()) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                pins.forEach { pin ->
                    AgentCard {
                        Row(
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp).fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text(pin.name, style = MaterialTheme.typography.titleMedium)
                                Text(pin.nodeId, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                            }
                            TextButton(onClick = {
                                scope.launch {
                                    val res = withContext(Dispatchers.IO) {
                                        runCatching {
                                            client.session?.clearNodePin(pin.name)
                                                ?: user?.let { api.clearNodePin(it, pin.name) }
                                                ?: false
                                        }
                                    }
                                    res.onSuccess {
                                        pins = pins.filterNot { it.name == pin.name }
                                        status = "Cleared pin for ${pin.name}."
                                    }.onFailure { status = it.message ?: "Couldn't clear pin." }
                                }
                            }) {
                                Text("Clear")
                            }
                        }
                    }
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            SecondaryButton("Signed grants", onClick = { loadGrants() }, modifier = Modifier.weight(1f).testTag("grants-button"))
            SecondaryButton("Import grant", onClick = {
                grantJsonDraft = ""
                showImportGrant = true
            }, modifier = Modifier.weight(1f))
        }
        if (grants.isNotEmpty()) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                grants.forEach { grant ->
                    AgentCard {
                        Row(
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp).fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text(grant.nodeId.take(16) + "…", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleMedium)
                                val expiryText = if (grant.expUnix >= 253_402_300_799L) "permanent" else "exp ${grant.expUnix}"
                                SupportingText("${grant.preset} · $expiryText")
                            }
                            TextButton(onClick = {
                                scope.launch {
                                    val res = withContext(Dispatchers.IO) {
                                        runCatching {
                                            client.session?.deleteGrant(grant.nodeId)
                                                ?: user?.let { api.deleteGrant(it, grant.nodeId) }
                                                ?: false
                                        }
                                    }
                                    res.onSuccess {
                                        grants = grants.filterNot { it.nodeId == grant.nodeId }
                                        status = "Deleted grant for ${grant.nodeId.take(12)}…."
                                    }.onFailure { status = it.message ?: "Couldn't delete grant." }
                                }
                            }) {
                                Text("Delete")
                            }
                        }
                    }
                }
            }
        }
        if (status.isNotEmpty()) {
            StatusLine(status, problem = looksLikeProblem(status) || isAuthFailure(status))
        }
        AgentDivider()
        SecondaryButton("Admin token", onAdmin, Modifier.fillMaxWidth())
        SecondaryButton("Log out", onLogout, Modifier.fillMaxWidth().testTag("logout"))
    }
    if (showImportGrant) {
        AlertDialog(
            onDismissRequest = { showImportGrant = false },
            title = { Text("Import signed grant") },
            text = {
                AgentField(
                    grantJsonDraft,
                    { grantJsonDraft = it },
                    "Grant JSON",
                    Modifier.fillMaxWidth(),
                    singleLine = false,
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val raw = grantJsonDraft.trim()
                    showImportGrant = false
                    scope.launch {
                        val res = withContext(Dispatchers.IO) {
                            runCatching {
                                client.session?.importGrant(raw)
                                    ?: user?.let { api.importGrant(it, raw) }
                                    ?: error("Not connected")
                            }
                        }
                        res.onSuccess {
                            status = "Imported grant for ${it.nodeId.take(12)}…."
                            loadGrants()
                        }.onFailure { status = it.message ?: "Couldn't import grant." }
                    }
                }) { Text("Import") }
            },
            dismissButton = {
                TextButton(onClick = { showImportGrant = false }) { Text("Cancel") }
            },
        )
    }
}
