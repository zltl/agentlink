package app.agentlink.node

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.DisplayMetrics
import android.view.Display
import android.view.WindowManager
import java.io.ByteArrayOutputStream

data class JpegFrame(val bytes: ByteArray, val width: Int, val height: Int)

class ScreenGrabber {
    private val lock = Any()
    private var appContext: Context? = null
    private var displayManager: DisplayManager? = null
    private var displayListener: DisplayManager.DisplayListener? = null
    private var projection: MediaProjection? = null
    private var reader: ImageReader? = null
    private var display: VirtualDisplay? = null
    private var width = 0
    private var height = 0
    private var densityDpi = 0
    private var lastFrame: JpegFrame? = null

    val active: Boolean
        get() = synchronized(lock) { projection != null }

    fun attach(context: Context, resultCode: Int, data: Intent) {
        val app = context.applicationContext
        synchronized(lock) {
            releaseLocked()
            val manager = app.getSystemService(MediaProjectionManager::class.java)
            val created = manager.getMediaProjection(resultCode, data) ?: return
            val mainHandler = Handler(Looper.getMainLooper())
            created.registerCallback(object : MediaProjection.Callback() {
                override fun onStop() {
                    release()
                }
            }, mainHandler)
            appContext = app
            projection = created
            rebuildDisplayLocked(app, created)
            val dm = app.getSystemService(DisplayManager::class.java)
            if (dm != null) {
                val listener = object : DisplayManager.DisplayListener {
                    override fun onDisplayAdded(displayId: Int) = Unit
                    override fun onDisplayRemoved(displayId: Int) = Unit
                    override fun onDisplayChanged(displayId: Int) {
                        if (displayId != Display.DEFAULT_DISPLAY) return
                        synchronized(lock) {
                            val activeProj = projection ?: return
                            val ctx = appContext ?: return
                            val (nextW, nextH, nextDpi) = targetSize(ctx)
                            if (nextW != width || nextH != height || nextDpi != densityDpi) {
                                rebuildDisplayLocked(ctx, activeProj)
                            }
                        }
                    }
                }
                dm.registerDisplayListener(listener, mainHandler)
                displayManager = dm
                displayListener = listener
            }
        }
    }

    fun jpeg(quality: Int): JpegFrame? {
        synchronized(lock) {
            val image = reader?.acquireLatestImage() ?: return lastFrame
            try {
                val plane = image.planes.firstOrNull() ?: return lastFrame
                val buffer = plane.buffer
                buffer.rewind()
                val pixelStride = plane.pixelStride
                val rowStride = plane.rowStride
                val rowPadding = rowStride - pixelStride * width
                val bitmapWidth = width + (rowPadding / pixelStride).coerceAtLeast(0)
                val raw = Bitmap.createBitmap(bitmapWidth, height, Bitmap.Config.ARGB_8888)
                raw.copyPixelsFromBuffer(buffer)
                val cropped = if (bitmapWidth == width) raw else Bitmap.createBitmap(raw, 0, 0, width, height)
                val out = ByteArrayOutputStream()
                cropped.compress(Bitmap.CompressFormat.JPEG, quality.coerceIn(30, 80), out)
                if (cropped !== raw) cropped.recycle()
                raw.recycle()
                val frame = JpegFrame(out.toByteArray(), width, height)
                lastFrame = frame
                return frame
            } finally {
                image.close()
            }
        }
    }

    fun release() {
        synchronized(lock) { releaseLocked() }
    }

    private fun rebuildDisplayLocked(context: Context, activeProjection: MediaProjection) {
        display?.release()
        reader?.close()
        display = null
        reader = null
        lastFrame = null
        val (w, h, dpi) = targetSize(context)
        val images = ImageReader.newInstance(w, h, PixelFormat.RGBA_8888, 2)
        val virtual = activeProjection.createVirtualDisplay(
            "agentlink",
            w,
            h,
            dpi,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
            images.surface,
            null,
            null,
        )
        reader = images
        display = virtual
        width = w
        height = h
        densityDpi = dpi
    }

    private fun targetSize(context: Context): Triple<Int, Int, Int> {
        val metrics = currentDisplayMetrics(context)
        var w = metrics.widthPixels
        var h = metrics.heightPixels
        val maxEdge = 720
        if (w >= h && w > maxEdge) {
            h = (h * (maxEdge.toFloat() / w)).toInt().coerceAtLeast(2)
            w = maxEdge
        } else if (h > maxEdge) {
            w = (w * (maxEdge.toFloat() / h)).toInt().coerceAtLeast(2)
            h = maxEdge
        }
        w = w.coerceAtLeast(2)
        h = h.coerceAtLeast(2)
        val dpi = metrics.densityDpi.coerceAtLeast(DisplayMetrics.DENSITY_DEFAULT)
        return Triple(w, h, dpi)
    }

    private fun releaseLocked() {
        displayListener?.let { listener ->
            runCatching { displayManager?.unregisterDisplayListener(listener) }
        }
        displayListener = null
        displayManager = null
        display?.release()
        reader?.close()
        projection?.stop()
        display = null
        reader = null
        projection = null
        appContext = null
        lastFrame = null
        width = 0
        height = 0
        densityDpi = 0
    }
}

internal fun currentDisplayMetrics(context: Context): DisplayMetrics {
    val out = DisplayMetrics()
    out.setTo(context.resources.displayMetrics)
    if (Build.VERSION.SDK_INT >= 30) {
        val wm = context.getSystemService(WindowManager::class.java)
        val bounds = runCatching { wm?.maximumWindowMetrics?.bounds }.getOrNull()
        if (bounds != null && bounds.width() > 0 && bounds.height() > 0) {
            out.widthPixels = bounds.width()
            out.heightPixels = bounds.height()
            return out
        }
    }
    val dm = context.getSystemService(DisplayManager::class.java)
    val defaultDisplay = dm?.getDisplay(Display.DEFAULT_DISPLAY)
    if (defaultDisplay != null) {
        @Suppress("DEPRECATION")
        defaultDisplay.getRealMetrics(out)
    }
    return out
}
