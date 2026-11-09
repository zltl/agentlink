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
import android.os.Handler
import android.os.Looper
import android.util.DisplayMetrics
import android.view.WindowManager
import java.io.ByteArrayOutputStream

data class JpegFrame(val bytes: ByteArray, val width: Int, val height: Int)

class ScreenGrabber {
    private val lock = Any()
    private var projection: MediaProjection? = null
    private var reader: ImageReader? = null
    private var display: VirtualDisplay? = null
    private var width = 0
    private var height = 0

    val active: Boolean
        get() = synchronized(lock) { projection != null }

    fun attach(context: Context, resultCode: Int, data: Intent) {
        synchronized(lock) {
            releaseLocked()
            val manager = context.getSystemService(MediaProjectionManager::class.java)
            val created = manager.getMediaProjection(resultCode, data) ?: return
            created.registerCallback(object : MediaProjection.Callback() {
                override fun onStop() {
                    release()
                }
            }, Handler(Looper.getMainLooper()))
            val metrics = realMetrics(context)
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
            val images = ImageReader.newInstance(w, h, PixelFormat.RGBA_8888, 2)
            val virtual = created.createVirtualDisplay(
                "agentlink",
                w,
                h,
                metrics.densityDpi,
                DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                images.surface,
                null,
                null,
            )
            projection = created
            reader = images
            display = virtual
            width = w
            height = h
        }
    }

    fun jpeg(quality: Int): JpegFrame? {
        synchronized(lock) {
            val image = reader?.acquireLatestImage() ?: return null
            try {
                val plane = image.planes.firstOrNull() ?: return null
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
                return JpegFrame(out.toByteArray(), width, height)
            } finally {
                image.close()
            }
        }
    }

    fun release() {
        synchronized(lock) { releaseLocked() }
    }

    private fun releaseLocked() {
        display?.release()
        reader?.close()
        projection?.stop()
        display = null
        reader = null
        projection = null
        width = 0
        height = 0
    }

    private fun realMetrics(context: Context): DisplayMetrics {
        val metrics = DisplayMetrics()
        val window = context.getSystemService(WindowManager::class.java)
        @Suppress("DEPRECATION")
        window.defaultDisplay.getRealMetrics(metrics)
        return metrics
    }
}
