package app.agentlink.model

import kotlin.math.min

/** 1× is the letterboxed fit. Pinch cannot shrink the desktop past that. */
const val DESKTOP_MIN_SCALE = 1f

/** Enough to read a region of a remote screen without becoming unbounded. */
const val DESKTOP_MAX_SCALE = 8f

private const val FIT_EPSILON = 0.001f

data class Letterbox(
    val imageLeft: Float,
    val imageTop: Float,
    val imageWidth: Float,
    val imageHeight: Float,
)

/**
 * Scale is relative to [letterbox]. Offsets are view pixels from that centered fit.
 * A fitted viewport has scale 1 and zero offset.
 */
data class DesktopViewport(
    val scale: Float = DESKTOP_MIN_SCALE,
    val offsetX: Float = 0f,
    val offsetY: Float = 0f,
) {
    fun isFitted(): Boolean = scale <= DESKTOP_MIN_SCALE + FIT_EPSILON
}

enum class OneFingerRelease { Tap, Swipe, Pan }

fun letterbox(viewW: Float, viewH: Float, imageW: Float, imageH: Float): Letterbox {
    if (viewW <= 0f || viewH <= 0f || imageW <= 0f || imageH <= 0f) {
        return Letterbox(0f, 0f, 0f, 0f)
    }
    val scale = min(viewW / imageW, viewH / imageH)
    val width = imageW * scale
    val height = imageH * scale
    return Letterbox((viewW - width) / 2f, (viewH - height) / 2f, width, height)
}

/** Normalized coordinates in the remote screenshot, or null when the point misses the image. */
fun mapTouch(box: Letterbox, x: Float, y: Float): Pair<Float, Float>? {
    if (box.imageWidth <= 0f || box.imageHeight <= 0f) return null
    val nx = (x - box.imageLeft) / box.imageWidth
    val ny = (y - box.imageTop) / box.imageHeight
    if (nx < 0f || ny < 0f || nx > 1f || ny > 1f) return null
    return nx to ny
}

fun gestureFromDrag(start: Pair<Float, Float>, end: Pair<Float, Float>, slop: Float = 0.02f): String {
    val dx = end.first - start.first
    val dy = end.second - start.second
    return if (dx * dx + dy * dy < slop * slop) "tap" else "swipe"
}

/** Letterboxed fit, then the current pinch scale and pan. */
fun displayedFrame(
    viewW: Float,
    viewH: Float,
    imageW: Float,
    imageH: Float,
    viewport: DesktopViewport,
): Letterbox {
    val fit = letterbox(viewW, viewH, imageW, imageH)
    return placeFrame(viewW, viewH, fit, viewport)
}

fun mapDesktopTouch(
    viewW: Float,
    viewH: Float,
    imageW: Float,
    imageH: Float,
    viewport: DesktopViewport,
    x: Float,
    y: Float,
): Pair<Float, Float>? {
    return mapTouch(displayedFrame(viewW, viewH, imageW, imageH, viewport), x, y)
}

/**
 * One finger at fit is a remote tap or swipe. Once zoomed, a drag pans locally and a
 * short press is still a tap at the point under the finger.
 */
fun oneFingerRelease(
    scale: Float,
    distancePx: Float,
    slopPx: Float,
    start: Pair<Float, Float>,
    end: Pair<Float, Float>,
): OneFingerRelease {
    val fitted = scale <= DESKTOP_MIN_SCALE + FIT_EPSILON
    if (!fitted && distancePx > slopPx) return OneFingerRelease.Pan
    if (distancePx <= slopPx || gestureFromDrag(start, end) == "tap") return OneFingerRelease.Tap
    return OneFingerRelease.Swipe
}

/** Pinch around [focusX]/[focusY] in view pixels. The point under the fingers stays put. */
fun zoomViewport(
    viewW: Float,
    viewH: Float,
    imageW: Float,
    imageH: Float,
    viewport: DesktopViewport,
    focusX: Float,
    focusY: Float,
    zoomFactor: Float,
): DesktopViewport {
    if (viewW <= 0f || viewH <= 0f || zoomFactor <= 0f) return viewport
    val fit = letterbox(viewW, viewH, imageW, imageH)
    if (fit.imageWidth <= 0f || fit.imageHeight <= 0f) return viewport
    val oldScale = viewport.scale.coerceIn(DESKTOP_MIN_SCALE, DESKTOP_MAX_SCALE)
    val newScale = (oldScale * zoomFactor).coerceIn(DESKTOP_MIN_SCALE, DESKTOP_MAX_SCALE)
    val before = placeFrame(viewW, viewH, fit, viewport.copy(scale = oldScale))
    val nx = (focusX - before.imageLeft) / before.imageWidth
    val ny = (focusY - before.imageTop) / before.imageHeight
    val width = fit.imageWidth * newScale
    val height = fit.imageHeight * newScale
    val fitCenterX = fit.imageLeft + fit.imageWidth / 2f
    val fitCenterY = fit.imageTop + fit.imageHeight / 2f
    val offsetX = (focusX - nx * width) - fitCenterX + width / 2f
    val offsetY = (focusY - ny * height) - fitCenterY + height / 2f
    val (clampedX, clampedY) = clampedOffset(viewW, viewH, fit, newScale, offsetX, offsetY)
    return DesktopViewport(newScale, clampedX, clampedY)
}

/**
 * Move the zoomed image with the finger. At fit the image stays centered.
 * Scale is kept even for a tiny pinch so the next event can accumulate.
 */
fun panViewport(
    viewW: Float,
    viewH: Float,
    imageW: Float,
    imageH: Float,
    viewport: DesktopViewport,
    dx: Float,
    dy: Float,
): DesktopViewport {
    val scale = viewport.scale.coerceIn(DESKTOP_MIN_SCALE, DESKTOP_MAX_SCALE)
    if (scale <= DESKTOP_MIN_SCALE) return DesktopViewport()
    val fit = letterbox(viewW, viewH, imageW, imageH)
    if (fit.imageWidth <= 0f || fit.imageHeight <= 0f) return viewport
    val (clampedX, clampedY) = clampedOffset(
        viewW,
        viewH,
        fit,
        scale,
        viewport.offsetX + dx,
        viewport.offsetY + dy,
    )
    return DesktopViewport(scale, clampedX, clampedY)
}

private fun placeFrame(viewW: Float, viewH: Float, fit: Letterbox, viewport: DesktopViewport): Letterbox {
    if (fit.imageWidth <= 0f || fit.imageHeight <= 0f) return fit
    val scale = viewport.scale.coerceIn(DESKTOP_MIN_SCALE, DESKTOP_MAX_SCALE)
    val width = fit.imageWidth * scale
    val height = fit.imageHeight * scale
    val (offsetX, offsetY) = clampedOffset(viewW, viewH, fit, scale, viewport.offsetX, viewport.offsetY)
    val fitCenterX = fit.imageLeft + fit.imageWidth / 2f
    val fitCenterY = fit.imageTop + fit.imageHeight / 2f
    return Letterbox(
        imageLeft = fitCenterX + offsetX - width / 2f,
        imageTop = fitCenterY + offsetY - height / 2f,
        imageWidth = width,
        imageHeight = height,
    )
}

private fun clampedOffset(
    viewW: Float,
    viewH: Float,
    fit: Letterbox,
    scale: Float,
    offsetX: Float,
    offsetY: Float,
): Pair<Float, Float> {
    val fitCenterX = fit.imageLeft + fit.imageWidth / 2f
    val fitCenterY = fit.imageTop + fit.imageHeight / 2f
    return clampAxis(viewW, fit.imageWidth * scale, fitCenterX, offsetX) to
        clampAxis(viewH, fit.imageHeight * scale, fitCenterY, offsetY)
}

private fun clampAxis(view: Float, length: Float, fitCenter: Float, offset: Float): Float {
    if (length <= view + 0.5f) return 0f
    val max = length / 2f - fitCenter
    val min = view - length / 2f - fitCenter
    return offset.coerceIn(min, max)
}
