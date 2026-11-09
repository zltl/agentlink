package app.agentlink.model

enum class ConsentStep(val title: String) {
    Notifications("Notifications"),
    AppStorage("App storage"),
    Commands("Commands"),
    Folders("Folders you pick"),
    AllFiles("All files"),
    ScreenCapture("Screen capture"),
    Accessibility("Accessibility"),
    Shizuku("Shizuku"),
    Root("Root"),
    Review("Review"),
}

data class ConsentChoices(
    val notifications: Boolean = false,
    val appStorage: Boolean = false,
    val commands: Boolean = false,
    val folders: Boolean = false,
    val allFiles: Boolean = false,
    val screenCapture: Boolean = false,
    val liveStream: Boolean = false,
    val accessibility: Boolean = false,
    val shizuku: Boolean = false,
    val root: Boolean = false,
    val visited: Set<ConsentStep> = emptySet(),
)

data class PolicyCeiling(
    val allowRead: Boolean,
    val allowWrite: Boolean,
    val allowExec: Boolean,
    val allowDesktop: Boolean,
    val allowDesktopStream: Boolean,
    val allowRemoteView: Boolean,
    val allowRemoteControl: Boolean,
)

fun consentSteps(): List<ConsentStep> = ConsentStep.entries.toList()

fun ceilingOf(choices: ConsentChoices): PolicyCeiling {
    val view = choices.screenCapture && choices.liveStream
    return PolicyCeiling(
        allowRead = choices.appStorage,
        allowWrite = choices.appStorage,
        allowExec = choices.commands,
        allowDesktop = choices.screenCapture,
        allowDesktopStream = view,
        allowRemoteView = view,
        allowRemoteControl = view && choices.accessibility,
    )
}

fun decisionsComplete(choices: ConsentChoices): Boolean {
    val required = ConsentStep.entries.filter { it != ConsentStep.Review }
    return required.all { it in choices.visited } && choices.appStorage
}

fun consentBody(step: ConsentStep): String = when (step) {
    ConsentStep.Notifications ->
        "The node runs as a foreground service and keeps a notification up so Android does not stop the outbound connection. Allow notifications if you want that notice to stay visible. Declining does not stop the service, but the system may hide it."
    ConsentStep.AppStorage ->
        "This phone will read and write files under its private app storage (app:/files and app:/cache). That storage is the default root. The audit log and device info are read-only virtual files. This is required to run as a node."
    ConsentStep.Commands ->
        "Allowing commands lets a paired client run programs in the app sandbox. An interactive shell is a real PTY, so full-screen programs can use the terminal size. That is not a root shell. Output and the exit code are audited. Skip this if the phone should only serve files."
    ConsentStep.Folders ->
        "You can grant specific folders with the system picker. Clients then use saf:/<id>/… paths. Bytes for a fast transfer are staged in app cache and copied back before the client is told the write finished. Skip this to keep access inside app storage."
    ConsentStep.AllFiles ->
        "All-files access lets clients use storage:/ for shared storage. It is broader than a single folder. It is optional, and Android will show its own settings screen. Skip this unless you want that."
    ConsentStep.ScreenCapture ->
        "Screen capture lets a client take screenshots through a media projection. Android shows a system dialog every time capture starts, and the node notification stays visible. Skip this to keep allow_desktop off."
    ConsentStep.Accessibility ->
        "Input and the UI tree need the agentlink accessibility service: taps, swipes, key events into the focused field, global actions, and clicking a labeled element. On Android 13 and newer the service sends raw key events when the editor accepts them. Otherwise it replaces the field text. The service can see on-screen text. Skip this to leave input disabled."
    ConsentStep.Shizuku ->
        "Shizuku can run the same commands through a shell you already started with wireless debugging or root. Agentlink does not start Shizuku. Leave this off unless you want that wider shell."
    ConsentStep.Root ->
        "Root runs commands with su. That can change anything the superuser allows. Leave this off unless you explicitly want root commands. It is off unless you press Allow."
    ConsentStep.Review ->
        "These choices are the phone's permission ceiling. The relay can grant less, never more. Every file, command, screenshot, and input operation is written to the audit log."
}

fun ceilingSummary(choices: ConsentChoices): List<String> {
    val ceiling = ceilingOf(choices)
    return listOf(
        if (ceiling.allowRead) {
            "Files: read and write inside app storage" +
                (if (choices.folders) ", plus folders you picked" else "") +
                (if (choices.allFiles) ", plus all-files storage" else "") +
                "."
        } else {
            "Files: off. Allow app storage before this phone can be a node."
        },
        if (ceiling.allowExec) {
            val extra = when {
                choices.root -> " Root was opted in."
                choices.shizuku -> " Shizuku was opted in when it is running."
                else -> " Commands stay inside the app sandbox shell."
            }
            "Commands: allowed.$extra"
        } else {
            "Commands: off."
        },
        if (ceiling.allowDesktop) {
            val input = if (choices.accessibility) {
                " Taps, swipes, typing, and the UI tree use the accessibility service."
            } else {
                " Input stays off until accessibility is enabled."
            }
            "Screen capture: allowed.$input"
        } else {
            "Screen capture and input: off."
        },
        if (ceiling.allowDesktopStream) {
            val control = if (ceiling.allowRemoteControl) {
                " Remote view and remote control are on."
            } else {
                " Remote view is on. Stream input stays off until accessibility is enabled."
            }
            "Live stream flag: on. This phone still answers webrtc_signal with a screenshot fallback.$control"
        } else {
            "Live stream flag: off. Remote view and remote control stay off."
        },
        if (choices.notifications) {
            "A persistent notification stays up while the node is connected."
        } else {
            "Notification permission was declined. Android may hide the node notification."
        },
    )
}
