package app.agentlink.ui

import android.media.MediaCodec
import android.media.MediaCodecList
import android.media.MediaFormat
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.view.Surface
import android.view.TextureView
import app.agentlink.model.avcAccessUnit
import app.agentlink.model.isSoftwareAvcDecoder
import app.agentlink.model.letterbox
import app.agentlink.model.preferAvcDecoder
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicReference

/**
 * Hardware AVC decode of Annex-B access units onto a [TextureView].
 *
 * Pinch-zoom and fullscreen chrome stay on the desktop column. This view only
 * letterboxes the picture so the existing touch mapping still lines up.
 */
class H264Player(context: android.content.Context) {
    val view: TextureView = TextureView(context)
    private val thread = HandlerThread("agentlink-h264").also { it.start() }
    private val handler = Handler(thread.looper)
    private val failure = AtomicReference<String?>(null)
    private val label = AtomicReference("decoder")
    private var codec: MediaCodec? = null
    private var surface: Surface? = null
    private var configured = false
    private var width = 0
    private var height = 0
    private var lastKeyframe: ByteArray? = null
    private var timestampUs = 0L
    @Volatile private var released = false

    init {
        view.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
            override fun onSurfaceTextureAvailable(texture: android.graphics.SurfaceTexture, w: Int, h: Int) {
                val created = Surface(texture)
                handler.post {
                    releaseSurface()
                    surface = created
                    applyBufferSize()
                    replayKeyframe()
                }
            }

            override fun onSurfaceTextureSizeChanged(texture: android.graphics.SurfaceTexture, w: Int, h: Int) {
                handler.post { applyBufferSize() }
            }

            override fun onSurfaceTextureDestroyed(texture: android.graphics.SurfaceTexture): Boolean {
                handler.post {
                    releaseCodec()
                    releaseSurface()
                }
                return true
            }

            override fun onSurfaceTextureUpdated(texture: android.graphics.SurfaceTexture) = Unit
        }
    }

    fun setVideoSize(videoWidth: Int, videoHeight: Int) {
        handler.post {
            width = videoWidth
            height = videoHeight
            applyBufferSize()
            replayKeyframe()
        }
    }

    fun submit(annexB: ByteArray, keyframe: Boolean) {
        if (released) return
        val copy = annexB.copyOf()
        handler.post {
            if (released) return@post
            val unit = avcAccessUnit(copy) ?: return@post
            if (unit.keyframe || keyframe) lastKeyframe = copy
            if (!configured) {
                val config = unit.config
                if (config != null && (unit.keyframe || keyframe)) {
                    if (!startCodec(config)) return@post
                } else {
                    return@post
                }
            }
            if (configured) queueSample(unit.sample, unit.keyframe || keyframe)
        }
    }

    fun failure(): String? = failure.get()

    fun decoderLabel(): String = label.get()

    fun dispose() {
        if (released) return
        released = true
        handler.post {
            releaseCodec()
            releaseSurface()
        }
        thread.quitSafely()
    }

    private fun replayKeyframe() {
        val bytes = lastKeyframe ?: return
        if (configured || surface == null || width <= 0 || height <= 0) return
        val unit = avcAccessUnit(bytes) ?: return
        val config = unit.config ?: return
        if (startCodec(config)) queueSample(unit.sample, true)
    }

    private fun startCodec(config: ByteArray): Boolean {
        val target = surface ?: return false
        if (width <= 0 || height <= 0 || configured) return configured
        val names = avcDecoderNames()
        val preferred = preferAvcDecoder(names)
        val order = ArrayList<String>()
        if (preferred != null) order.add(preferred)
        names.filter { isSoftwareAvcDecoder(it) && it !in order }.forEach { order.add(it) }
        if (order.isEmpty()) {
            return startByType(config, target)
        }
        var last = "no AVC decoder"
        for (name in order) {
            try {
                val created = MediaCodec.createByCodecName(name)
                if (configure(created, config, target, name)) return true
            } catch (err: Exception) {
                last = err.message ?: err.javaClass.simpleName
            }
        }
        failure.set(last)
        return false
    }

    private fun startByType(config: ByteArray, target: Surface): Boolean {
        return try {
            val created = MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_VIDEO_AVC)
            configure(created, config, target, created.name)
        } catch (err: Exception) {
            failure.set(err.message ?: "AVC decoder did not start")
            false
        }
    }

    private fun configure(created: MediaCodec, config: ByteArray, target: Surface, name: String): Boolean {
        return try {
            val format = MediaFormat.createVideoFormat(MediaFormat.MIMETYPE_VIDEO_AVC, width, height)
            format.setByteBuffer("csd-0", ByteBuffer.wrap(config))
            format.setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, 1 shl 20)
            format.setInteger(MediaFormat.KEY_FRAME_RATE, 30)
            format.setFloat(MediaFormat.KEY_OPERATING_RATE, 30f)
            format.setInteger(MediaFormat.KEY_PRIORITY, 0)
            if (Build.VERSION.SDK_INT >= 30) {
                format.setInteger(MediaFormat.KEY_LOW_LATENCY, 1)
            }
            created.configure(format, target, null, 0)
            created.start()
            codec = created
            configured = true
            label.set(if (isSoftwareAvcDecoder(name)) "sw decode" else "hw decode")
            failure.set(null)
            true
        } catch (err: Exception) {
            runCatching { created.release() }
            failure.set(err.message ?: "AVC decoder did not start")
            false
        }
    }

    private fun queueSample(sample: ByteArray, keyframe: Boolean) {
        val current = codec ?: return
        try {
            val index = current.dequeueInputBuffer(10_000)
            if (index < 0) return
            val buffer = current.getInputBuffer(index) ?: return
            buffer.clear()
            buffer.put(sample)
            val flags = if (keyframe) MediaCodec.BUFFER_FLAG_KEY_FRAME else 0
            timestampUs += 33_333
            current.queueInputBuffer(index, 0, sample.size, timestampUs, flags)
            drain()
        } catch (err: Exception) {
            failure.set(err.message ?: "decoder stopped")
            releaseCodec()
        }
    }

    private fun drain() {
        val current = codec ?: return
        val info = MediaCodec.BufferInfo()
        while (true) {
            val index = current.dequeueOutputBuffer(info, 0)
            when {
                index >= 0 -> current.releaseOutputBuffer(index, true)
                else -> return
            }
        }
    }

    private fun applyBufferSize() {
        val texture = view.surfaceTexture ?: return
        if (width > 0 && height > 0) texture.setDefaultBufferSize(width, height)
    }

    private fun releaseCodec() {
        val current = codec ?: return
        codec = null
        configured = false
        runCatching { current.stop() }
        runCatching { current.release() }
    }

    private fun releaseSurface() {
        val current = surface ?: return
        surface = null
        runCatching { current.release() }
    }

    private fun avcDecoderNames(): List<String> {
        val infos = MediaCodecList(MediaCodecList.REGULAR_CODECS).codecInfos
        return infos.mapNotNull { info ->
            if (info.isEncoder) return@mapNotNull null
            val avc = info.supportedTypes.any { it.equals(MediaFormat.MIMETYPE_VIDEO_AVC, ignoreCase = true) }
            if (avc) info.name else null
        }
    }
}

fun applyLetterbox(view: TextureView, videoWidth: Int, videoHeight: Int) {
    val viewW = view.width.toFloat()
    val viewH = view.height.toFloat()
    val box = letterbox(viewW, viewH, videoWidth.toFloat(), videoHeight.toFloat())
    if (viewW <= 0f || viewH <= 0f || box.imageWidth <= 0f) return
    val matrix = android.graphics.Matrix()
    matrix.setScale(box.imageWidth / viewW, box.imageHeight / viewH, viewW / 2f, viewH / 2f)
    view.setTransform(matrix)
}
