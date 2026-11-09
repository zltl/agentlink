@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package app.agentlink.ui

import android.content.Intent
import android.net.Uri
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
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
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
import app.agentlink.bridge.LinkBridge
import app.agentlink.bridge.MachineRow
import app.agentlink.model.ConsentChoices
import app.agentlink.model.ConsentStep
import app.agentlink.model.consentSteps
import app.agentlink.model.resolveJoin
import app.agentlink.node.ConsentStore
import app.agentlink.node.NodeForegroundService
import app.agentlink.node.NodeRuntime
import app.agentlink.node.NodeSetup
import android.os.Handler
import android.os.Looper
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
    var relay by rememberSaveable { mutableStateOf(enroll?.server ?: user?.server ?: DEFAULT_RELAY) }
    var fingerprint by rememberSaveable { mutableStateOf(enroll?.fingerprint ?: user?.fingerprint ?: "") }
    var token by rememberSaveable { mutableStateOf(enroll?.token ?: "") }
    var name by rememberSaveable { mutableStateOf(enroll?.name ?: "") }
    var choices by remember { mutableStateOf(ConsentChoices()) }
    var step by remember { mutableStateOf(ConsentStep.Notifications) }
    var projection by remember { mutableStateOf<Intent?>(null) }
    var projectionCode by remember { mutableIntStateOf(0) }
    var settingsNote by remember { mutableStateOf("") }
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
        val opened = withContext(Dispatchers.IO) { runCatching { account.connect(current) } }
        if (!isActive || epoch.get() != started) return@LaunchedEffect
        if (opened.isSuccess) {
            linkedToken = current.accessToken
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
                    )
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
                        MachineAction.Files.pane -> FilesPane(client, machine)
                        MachineAction.Terminal.pane -> TerminalPane(client, machine, account)
                        MachineAction.Desktop.pane -> DesktopPane(client, machine, account)
                        MachineAction.Transfer.pane -> TransferPane(client, machine)
                        MachineAction.Audit.pane -> AuditPane(client, machine)
                        else -> MissingMachine(onBack = { nav.popBackStack() })
                    }
                }
            }
            composable(Routes.Settings) {
                SettingsPage(
                    user = user,
                    api = account,
                    note = settingsNote,
                    onActAsNode = {
                        val current = user
                        if (current == null) {
                            nav.navigate(Routes.Setup)
                        } else {
                            scope.launch {
                                val result = withContext(Dispatchers.IO) {
                                    runCatching { account.enrollAsNode(current, "phone") }
                                }
                                result.onSuccess {
                                    relay = current.server
                                    fingerprint = current.fingerprint
                                    token = ""
                                    name = "phone"
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
                        step = ConsentStep.Notifications
                        choices = ConsentChoices()
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
private fun PhonePage(onPair: () -> Unit, onStop: () -> Unit) {
    val running by NodeRuntime.running.collectAsState()
    val status by NodeRuntime.status.collectAsState()
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
                } else {
                    SupportingText("Pair this phone when another machine should be able to reach it.")
                }
            }
        }
        PrimaryButton("Pair this phone", onPair, Modifier.fillMaxWidth().testTag("pair-phone"))
        if (running) {
            SecondaryButton("Stop node", onStop, Modifier.fillMaxWidth())
        }
    }
}

@Composable
private fun SettingsPage(
    user: UserAccount?,
    api: AccountApi,
    note: String,
    onActAsNode: () -> Unit,
    onAdmin: () -> Unit,
    onLogout: () -> Unit,
    onAuthFailure: (String) -> Unit,
) {
    var devices by remember { mutableStateOf<List<DeviceRow>>(emptyList()) }
    var status by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    LaunchedEffect(note) { if (note.isNotEmpty()) status = note }
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
                            }
                        }
                    }
                }
            }
            PrimaryButton("Act as node", onActAsNode, Modifier.fillMaxWidth().testTag("act-node"))
        }
        if (status.isNotEmpty()) {
            StatusLine(status, problem = looksLikeProblem(status) || isAuthFailure(status))
        }
        AgentDivider()
        SecondaryButton("Admin token", onAdmin, Modifier.fillMaxWidth())
        SecondaryButton("Log out", onLogout, Modifier.fillMaxWidth().testTag("logout"))
    }
}
