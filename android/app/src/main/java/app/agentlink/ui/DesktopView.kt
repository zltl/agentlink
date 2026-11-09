package app.agentlink.ui

import android.view.ViewGroup
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.calculateCentroid
import androidx.compose.foundation.gestures.calculatePan
import androidx.compose.foundation.gestures.calculateZoom
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Fullscreen
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.key
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.PointerInputScope
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.positionChanged
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.DialogWindowProvider
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import app.agentlink.bridge.LiveCursor
import app.agentlink.bridge.MachineRow
import app.agentlink.model.DesktopViewport
import app.agentlink.model.OneFingerRelease
import app.agentlink.model.displayedFrame
import app.agentlink.model.mapDesktopTouch
import app.agentlink.model.oneFingerRelease
import app.agentlink.model.panViewport
import app.agentlink.model.zoomViewport
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONObject
import kotlin.math.hypot
import kotlin.math.roundToInt

@Composable
internal fun DesktopView(
    machine: MachineRow,
    capability: DesktopCapability,
    note: String,
    frame: ImageBitmap?,
    shotW: Int,
    shotH: Int,
    stream: Boolean,
    onStream: (Boolean) -> Unit,
    typed: String,
    onTyped: (String) -> Unit,
    onLive: () -> Unit,
    onInject: (JSONObject) -> Unit,
    fullscreen: Boolean,
    onFullscreenChange: (Boolean) -> Unit,
    viewport: DesktopViewport,
    onViewportChange: (DesktopViewport) -> Unit,
    livePlayer: H264Player? = null,
    cursor: LiveCursor? = null,
    emptyText: String? = null,
    liveButton: String = "Request live view",
    liveButtonEnabled: Boolean = true,
    onFixGrant: (() -> Unit)? = null,
) {
    val onViewportUpdated = rememberUpdatedState(onViewportChange)
    val onFullscreenUpdated = rememberUpdatedState(onFullscreenChange)
    val pictureText = emptyText ?: emptyFrameText(capability)
    // Entering or leaving immersive view always starts from Fit.
    LaunchedEffect(fullscreen, machine.id) {
        onViewportUpdated.value(DesktopViewport())
    }
    fun changeFullscreen(enabled: Boolean) {
        onViewportUpdated.value(DesktopViewport())
        onFullscreenUpdated.value(enabled)
    }
    BackHandler(enabled = fullscreen) { changeFullscreen(false) }
    if (fullscreen) {
        DesktopFullscreen(
            frame = frame,
            emptyText = pictureText,
            shotW = shotW,
            shotH = shotH,
            viewport = viewport,
            onViewportChange = onViewportChange,
            control = capability.control,
            onInject = onInject,
            livePlayer = livePlayer,
            cursor = cursor,
            onClose = { changeFullscreen(false) },
        )
    } else {
        DesktopEmbedded(
            machine = machine,
            capability = capability,
            note = note,
            frame = frame,
            shotW = shotW,
            shotH = shotH,
            stream = stream,
            onStream = onStream,
            typed = typed,
            onTyped = onTyped,
            onLive = onLive,
            onInject = onInject,
            onFullscreen = { changeFullscreen(true) },
            viewport = viewport,
            onViewportChange = onViewportChange,
            livePlayer = livePlayer,
            cursor = cursor,
            emptyText = pictureText,
            liveButton = liveButton,
            liveButtonEnabled = liveButtonEnabled,
            onFixGrant = onFixGrant,
        )
    }
}

@Composable
private fun DesktopEmbedded(
    machine: MachineRow,
    capability: DesktopCapability,
    note: String,
    frame: ImageBitmap?,
    shotW: Int,
    shotH: Int,
    stream: Boolean,
    onStream: (Boolean) -> Unit,
    typed: String,
    onTyped: (String) -> Unit,
    onLive: () -> Unit,
    onInject: (JSONObject) -> Unit,
    onFullscreen: () -> Unit,
    viewport: DesktopViewport,
    onViewportChange: (DesktopViewport) -> Unit,
    livePlayer: H264Player?,
    cursor: LiveCursor?,
    emptyText: String,
    liveButton: String,
    liveButtonEnabled: Boolean,
    onFixGrant: (() -> Unit)?,
) {
    BoxWithConstraints(Modifier.fillMaxSize().testTag("desktop-view")) {
        val landscape = maxWidth > maxHeight
        val problem = looksLikeProblem(note)
        if (landscape) {
            val scrim = MaterialTheme.colorScheme.surface.copy(alpha = 0.92f)
            Box(Modifier.fillMaxSize()) {
                RemoteFrame(
                    frame = frame,
                    emptyText = emptyText,
                    shotW = shotW,
                    shotH = shotH,
                    viewport = viewport,
                    onViewportChange = onViewportChange,
                    control = capability.control,
                    onInject = onInject,
                    backdrop = Color.Black,
                    livePlayer = livePlayer,
                    cursor = cursor,
                    modifier = Modifier.fillMaxSize().testTag("desktop-viewport"),
                )
                Column(
                    modifier = Modifier
                        .align(Alignment.TopCenter)
                        .fillMaxWidth()
                        .background(scrim)
                        .padding(horizontal = 12.dp, vertical = 4.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(
                        "${machine.name} · ${if (machine.online) "Online" else "Offline"}",
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    if (problem) {
                        AgentBanner(
                            note,
                            BannerTone.Error,
                            action = if (onFixGrant != null) "Fix grant" else null,
                            onAction = onFixGrant,
                        )
                    }
                    HeaderActions(
                        capability,
                        stream,
                        onStream,
                        onFullscreen,
                        note = if (problem) null else note,
                    )
                }
                DesktopControls(
                    capability = capability,
                    typed = typed,
                    onTyped = onTyped,
                    onLive = onLive,
                    onInject = onInject,
                    liveButton = liveButton,
                    liveButtonEnabled = liveButtonEnabled,
                    maxHeight = 132.dp,
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .fillMaxWidth()
                        .background(scrim)
                        .padding(horizontal = 12.dp, vertical = 6.dp),
                )
            }
        } else {
            Column(Modifier.fillMaxSize()) {
                Column(
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    MachineContextLine(machine)
                    AgentBanner(
                        note,
                        if (problem) BannerTone.Error else BannerTone.Info,
                        action = if (onFixGrant != null) "Fix grant" else null,
                        onAction = onFixGrant,
                    )
                    HeaderActions(capability, stream, onStream, onFullscreen)
                }
                RemoteFrame(
                    frame = frame,
                    emptyText = emptyText,
                    shotW = shotW,
                    shotH = shotH,
                    viewport = viewport,
                    onViewportChange = onViewportChange,
                    control = capability.control,
                    onInject = onInject,
                    backdrop = MaterialTheme.colorScheme.surfaceContainer,
                    livePlayer = livePlayer,
                    cursor = cursor,
                    modifier = Modifier.weight(1f).fillMaxWidth().testTag("desktop-viewport"),
                )
                DesktopControls(
                    capability = capability,
                    typed = typed,
                    onTyped = onTyped,
                    onLive = onLive,
                    onInject = onInject,
                    liveButton = liveButton,
                    liveButtonEnabled = liveButtonEnabled,
                    maxHeight = 220.dp,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                )
            }
        }
    }
}

@Composable
private fun HeaderActions(
    capability: DesktopCapability,
    stream: Boolean,
    onStream: (Boolean) -> Unit,
    onFullscreen: () -> Unit,
    note: String? = null,
) {
    Row(
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        val watchLabel = if (capability.screenshots) "Stream screenshots" else "Watch the screen"
        val canWatch = capability.screenshots || capability.live
        if (note != null) {
            Text(
                note,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
        } else if (canWatch) {
            Text(watchLabel, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        } else {
            Spacer(Modifier.weight(1f))
        }
        if (canWatch) {
            AgentSwitch(
                stream,
                onStream,
                Modifier.semantics { contentDescription = watchLabel }.testTag("desktop-stream"),
            )
        }
        FullscreenButton(onFullscreen)
    }
}

@Composable
private fun FullscreenButton(onClick: () -> Unit) {
    TextButton(
        onClick = onClick,
        modifier = Modifier.testTag("desktop-fullscreen").heightIn(min = 48.dp),
    ) {
        Icon(Icons.Filled.Fullscreen, contentDescription = null, modifier = Modifier.size(20.dp))
        Spacer(Modifier.width(6.dp))
        Text("Fullscreen")
    }
}

@Composable
private fun DesktopControls(
    capability: DesktopCapability,
    typed: String,
    onTyped: (String) -> Unit,
    onLive: () -> Unit,
    onInject: (JSONObject) -> Unit,
    liveButton: String,
    liveButtonEnabled: Boolean,
    maxHeight: Dp,
    modifier: Modifier = Modifier,
) {
    if (!capability.live && !capability.control) {
        if (capability.available) {
            SupportingText("Input stays off for this preset.", modifier.padding(vertical = 4.dp))
        }
        return
    }
    Column(
        modifier = modifier.heightIn(max = maxHeight).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        if (capability.live) {
            SecondaryButton(
                liveButton,
                onClick = onLive,
                modifier = Modifier.fillMaxWidth(),
                enabled = liveButtonEnabled,
            )
        }
        if (capability.control) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.horizontalScroll(rememberScrollState()),
            ) {
                listOf("back", "home", "recents", "notifications").forEach { name ->
                    SecondaryButton(name, onClick = { onInject(globalPayload(name)) })
                }
            }
            AgentField(typed, onTyped, "Type into the focused field", Modifier.fillMaxWidth())
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.horizontalScroll(rememberScrollState()),
            ) {
                PrimaryButton("Type", onClick = {
                    onInject(JSONObject().put("action", "type").put("text", typed))
                    onTyped("")
                })
                listOf("enter", "backspace", "tab", "escape", "up", "down", "left", "right").forEach { name ->
                    SecondaryButton(name, onClick = { onInject(keyPayload(name)) })
                }
            }
        } else if (capability.available) {
            SupportingText("Input stays off for this preset.")
        }
    }
}

@Composable
private fun DesktopFullscreen(
    frame: ImageBitmap?,
    emptyText: String,
    shotW: Int,
    shotH: Int,
    viewport: DesktopViewport,
    onViewportChange: (DesktopViewport) -> Unit,
    control: Boolean,
    onInject: (JSONObject) -> Unit,
    livePlayer: H264Player?,
    cursor: LiveCursor?,
    onClose: () -> Unit,
) {
    Dialog(
        onDismissRequest = onClose,
        properties = DialogProperties(
            dismissOnBackPress = true,
            dismissOnClickOutside = false,
            usePlatformDefaultWidth = false,
            decorFitsSystemWindows = false,
        ),
    ) {
        HideSystemBars()
        Box(
            Modifier
                .fillMaxSize()
                .background(Color.Black)
                .testTag("desktop-fullscreen-root"),
        ) {
            RemoteFrame(
                frame = frame,
                emptyText = emptyText,
                shotW = shotW,
                shotH = shotH,
                viewport = viewport,
                onViewportChange = onViewportChange,
                control = control,
                onInject = onInject,
                backdrop = Color.Black,
                livePlayer = livePlayer,
                cursor = cursor,
                modifier = Modifier.fillMaxSize().testTag("desktop-viewport"),
            )
            IconButton(
                onClick = onClose,
                modifier = Modifier
                    .align(Alignment.TopStart)
                    .windowInsetsPadding(WindowInsets.safeDrawing)
                    .padding(8.dp)
                    .background(Color.Black.copy(alpha = 0.55f), CircleShape)
                    .testTag("desktop-close"),
            ) {
                Icon(Icons.Filled.Close, contentDescription = "Close fullscreen", tint = Color.White)
            }
        }
    }
}

@Composable
private fun HideSystemBars() {
    val view = LocalView.current
    DisposableEffect(view) {
        val window = findDialogWindow(view)
        if (window == null) {
            onDispose { }
        } else {
            WindowCompat.setDecorFitsSystemWindows(window, false)
            val controller = WindowCompat.getInsetsController(window, view)
            controller.systemBarsBehavior = WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
            controller.isAppearanceLightStatusBars = false
            controller.isAppearanceLightNavigationBars = false
            controller.hide(WindowInsetsCompat.Type.systemBars())
            onDispose {
                controller.show(WindowInsetsCompat.Type.systemBars())
            }
        }
    }
}

private fun findDialogWindow(view: android.view.View): android.view.Window? {
    var current: android.view.ViewParent? = view.parent
    while (current != null) {
        if (current is DialogWindowProvider) return current.window
        current = current.parent
    }
    return null
}

@Composable
private fun RemoteFrame(
    frame: ImageBitmap?,
    emptyText: String,
    shotW: Int,
    shotH: Int,
    viewport: DesktopViewport,
    onViewportChange: (DesktopViewport) -> Unit,
    control: Boolean,
    onInject: (JSONObject) -> Unit,
    backdrop: Color,
    livePlayer: H264Player? = null,
    cursor: LiveCursor? = null,
    modifier: Modifier = Modifier,
) {
    val viewportState = rememberUpdatedState(viewport)
    val onViewportState = rememberUpdatedState(onViewportChange)
    val controlState = rememberUpdatedState(control)
    val onInjectState = rememberUpdatedState(onInject)
    val shotWState = rememberUpdatedState(shotW)
    val shotHState = rememberUpdatedState(shotH)
    var viewSize by remember { mutableStateOf(IntSize.Zero) }
    val viewState = rememberUpdatedState(viewSize)
    Box(
        modifier.clipToBounds().background(backdrop),
        contentAlignment = Alignment.Center,
    ) {
        if (livePlayer != null) {
            LiveSurface(
                player = livePlayer,
                shotW = shotW,
                shotH = shotH,
                viewport = viewport,
                onSize = { viewSize = it },
                pointer = Modifier.pointerInput(Unit) {
                    watchDesktop(
                        viewSize = { viewState.value },
                        shotW = { shotWState.value },
                        shotH = { shotHState.value },
                        viewport = { viewportState.value },
                        onViewport = { onViewportState.value(it) },
                        control = { controlState.value },
                        onInject = { onInjectState.value(it) },
                    )
                },
            )
            CursorMark(cursor, shotW, shotH, viewSize, viewport)
        } else if (frame == null) {
            Text(
                emptyText,
                style = MaterialTheme.typography.bodyLarge,
                color = if (backdrop == Color.Black) Color.White else MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.padding(24.dp),
            )
        } else {
            Image(
                bitmap = frame,
                contentDescription = "Remote screen",
                contentScale = ContentScale.Fit,
                modifier = Modifier
                    .fillMaxSize()
                    .testTag("desktop-screen")
                    .onSizeChanged { viewSize = it }
                    .pointerInput(Unit) {
                        watchDesktop(
                            viewSize = { viewState.value },
                            shotW = { shotWState.value },
                            shotH = { shotHState.value },
                            viewport = { viewportState.value },
                            onViewport = { onViewportState.value(it) },
                            control = { controlState.value },
                            onInject = { onInjectState.value(it) },
                        )
                    }
                    .graphicsLayer {
                        val scale = viewport.scale.coerceIn(1f, 8f)
                        scaleX = scale
                        scaleY = scale
                        translationX = viewport.offsetX
                        translationY = viewport.offsetY
                        clip = true
                    },
            )
        }
    }
}

@Composable
private fun LiveSurface(
    player: H264Player,
    shotW: Int,
    shotH: Int,
    viewport: DesktopViewport,
    onSize: (IntSize) -> Unit,
    pointer: Modifier,
) {
    // A TextureView has one parent. Fullscreen moves the same view into the dialog.
    key(player) {
        AndroidView(
            factory = {
                val texture = player.view
                (texture.parent as? ViewGroup)?.removeView(texture)
                texture
            },
            update = { view ->
                applyLetterbox(view, shotW, shotH)
                val scale = viewport.scale.coerceIn(1f, 8f)
                view.pivotX = view.width / 2f
                view.pivotY = view.height / 2f
                view.scaleX = scale
                view.scaleY = scale
                view.translationX = viewport.offsetX
                view.translationY = viewport.offsetY
            },
            modifier = Modifier
                .fillMaxSize()
                .testTag("desktop-screen")
                .semantics { contentDescription = "Remote screen" }
                .onSizeChanged(onSize)
                .then(pointer),
        )
    }
}

@Composable
private fun BoxScope.CursorMark(
    cursor: LiveCursor?,
    shotW: Int,
    shotH: Int,
    viewSize: IntSize,
    viewport: DesktopViewport,
) {
    val mark = cursor ?: return
    if (shotW <= 0 || shotH <= 0 || viewSize == IntSize.Zero) return
    val box = displayedFrame(
        viewSize.width.toFloat(),
        viewSize.height.toFloat(),
        shotW.toFloat(),
        shotH.toFloat(),
        viewport,
    )
    val left = box.imageLeft + (mark.x.toFloat() / shotW) * box.imageWidth
    val top = box.imageTop + (mark.y.toFloat() / shotH) * box.imageHeight
    Box(
        modifier = Modifier
            .align(Alignment.TopStart)
            .offset { IntOffset(left.roundToInt(), top.roundToInt()) }
            .size(10.dp)
            .background(Color.White.copy(alpha = 0.9f)),
    )
}

private suspend fun PointerInputScope.watchDesktop(
    viewSize: () -> IntSize,
    shotW: () -> Int,
    shotH: () -> Int,
    viewport: () -> DesktopViewport,
    onViewport: (DesktopViewport) -> Unit,
    control: () -> Boolean,
    onInject: (JSONObject) -> Unit,
) {
    coroutineScope {
        var pendingTap: Job? = null
        var lastTapAt = 0L
        var lastTapX = 0f
        var lastTapY = 0f
        awaitEachGesture {
            val down = awaitFirstDown(requireUnconsumed = false)
            pendingTap?.cancel()
            pendingTap = null
            val slop = viewConfiguration.touchSlop
            var transformed = false
            var panning = false
            val start = down.position
            var last = down.position
            var startNorm = mapAt(viewSize, shotW, shotH, viewport, start.x, start.y)
            var lastNorm = startNorm

            while (true) {
                val event = awaitPointerEvent()
                val pressed = event.changes.filter { it.pressed }
                if (pressed.isEmpty()) {
                    val up = event.changes.firstOrNull()
                    if (up != null) last = up.position
                    if (!transformed && !panning && control()) {
                        val from = startNorm
                        val to = lastNorm ?: from
                        if (from != null && to != null) {
                            val release = oneFingerRelease(
                                viewport().scale,
                                hypot(last.x - start.x, last.y - start.y),
                                slop,
                                from,
                                to,
                            )
                            when (release) {
                                OneFingerRelease.Tap -> {
                                    val now = up?.uptimeMillis ?: down.uptimeMillis
                                    val zoomed = !viewport().isFitted()
                                    val near = hypot(start.x - lastTapX, start.y - lastTapY) <= slop * 2f
                                    val quick = lastTapAt != 0L && now - lastTapAt <= viewConfiguration.doubleTapTimeoutMillis
                                    if (zoomed && quick && near) {
                                        onViewport(DesktopViewport())
                                        lastTapAt = 0L
                                    } else if (zoomed) {
                                        lastTapAt = now
                                        lastTapX = start.x
                                        lastTapY = start.y
                                        val nx = from.first
                                        val ny = from.second
                                        pendingTap = launch {
                                            delay(viewConfiguration.doubleTapTimeoutMillis)
                                            onInject(tapPayload(nx, ny))
                                        }
                                    } else {
                                        lastTapAt = now
                                        onInject(tapPayload(from.first, from.second))
                                    }
                                }
                                OneFingerRelease.Swipe -> onInject(swipePayload(from, to))
                                OneFingerRelease.Pan -> Unit
                            }
                        }
                    }
                    break
                }
                if (pressed.size >= 2) {
                    transformed = true
                    panning = false
                    val zoom = event.calculateZoom()
                    val pan = event.calculatePan()
                    val centroid = event.calculateCentroid(useCurrent = true)
                    val size = viewSize()
                    if (centroid != Offset.Unspecified && size.width > 0 && size.height > 0) {
                        val zoomed = zoomViewport(
                            size.width.toFloat(),
                            size.height.toFloat(),
                            shotW().toFloat(),
                            shotH().toFloat(),
                            viewport(),
                            centroid.x,
                            centroid.y,
                            zoom,
                        )
                        onViewport(
                            panViewport(
                                size.width.toFloat(),
                                size.height.toFloat(),
                                shotW().toFloat(),
                                shotH().toFloat(),
                                zoomed,
                                pan.x,
                                pan.y,
                            ),
                        )
                    }
                    event.changes.forEach { if (it.positionChanged()) it.consume() }
                } else {
                    val change = pressed.first()
                    val previous = last
                    last = change.position
                    val mapped = mapAt(viewSize, shotW, shotH, viewport, last.x, last.y)
                    if (mapped != null) lastNorm = mapped
                    val travel = hypot(last.x - start.x, last.y - start.y)
                    if (!transformed && !viewport().isFitted() && travel > slop) {
                        panning = true
                        val size = viewSize()
                        if (size.width > 0 && size.height > 0) {
                            onViewport(
                                panViewport(
                                    size.width.toFloat(),
                                    size.height.toFloat(),
                                    shotW().toFloat(),
                                    shotH().toFloat(),
                                    viewport(),
                                    last.x - previous.x,
                                    last.y - previous.y,
                                ),
                            )
                        }
                        change.consume()
                    } else if (travel > slop) {
                        change.consume()
                    }
                }
            }
        }
    }
}

private fun mapAt(
    viewSize: () -> IntSize,
    shotW: () -> Int,
    shotH: () -> Int,
    viewport: () -> DesktopViewport,
    x: Float,
    y: Float,
): Pair<Float, Float>? {
    val size = viewSize()
    if (size.width <= 0 || size.height <= 0) return null
    return mapDesktopTouch(
        size.width.toFloat(),
        size.height.toFloat(),
        shotW().toFloat(),
        shotH().toFloat(),
        viewport(),
        x,
        y,
    )
}

private fun emptyFrameText(capability: DesktopCapability): String {
    return if (capability.screenshots) "Waiting for a screenshot." else "No screenshot for this preset."
}

private fun tapPayload(x: Float, y: Float): JSONObject {
    return JSONObject().put("action", "tap").put("x", x.toDouble()).put("y", y.toDouble())
}

private fun swipePayload(from: Pair<Float, Float>, to: Pair<Float, Float>): JSONObject {
    return JSONObject()
        .put("action", "swipe")
        .put("x", from.first.toDouble())
        .put("y", from.second.toDouble())
        .put("x2", to.first.toDouble())
        .put("y2", to.second.toDouble())
        .put("duration_ms", 280)
}

private fun globalPayload(name: String): JSONObject {
    return JSONObject().put("action", "global").put("name", name)
}

private fun keyPayload(name: String): JSONObject {
    return JSONObject().put("action", "key").put("name", name)
}
