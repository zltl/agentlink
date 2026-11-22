package app.agentlink.model

import org.json.JSONObject
import java.util.Locale
import kotlin.math.roundToInt

const val LIVE_MAX_FPS = 30
const val LIVE_BITRATE = 2_000_000

/** One length-prefixed AVC sample, plus a codec config when SPS and PPS arrived. */
data class AvcUnit(val config: ByteArray?, val sample: ByteArray, val keyframe: Boolean)

fun annexBNals(bytes: ByteArray): List<ByteArray> {
    val starts = ArrayList<Int>()
    var index = 0
    while (index + 3 < bytes.size) {
        if (index + 4 <= bytes.size &&
            bytes[index] == 0.toByte() &&
            bytes[index + 1] == 0.toByte() &&
            bytes[index + 2] == 0.toByte() &&
            bytes[index + 3] == 1.toByte()
        ) {
            starts.add(index + 4)
            index += 4
            continue
        }
        if (bytes[index] == 0.toByte() && bytes[index + 1] == 0.toByte() && bytes[index + 2] == 1.toByte()) {
            starts.add(index + 3)
            index += 3
            continue
        }
        index++
    }
    val nals = ArrayList<ByteArray>(starts.size)
    for (nth in starts.indices) {
        val start = starts[nth]
        var end = if (nth + 1 < starts.size) starts[nth + 1] else bytes.size
        if (nth + 1 < starts.size) {
            if (end >= 4 &&
                bytes[end - 4] == 0.toByte() &&
                bytes[end - 3] == 0.toByte() &&
                bytes[end - 2] == 0.toByte() &&
                bytes[end - 1] == 1.toByte()
            ) {
                end -= 4
            } else if (end >= 3 &&
                bytes[end - 3] == 0.toByte() &&
                bytes[end - 2] == 0.toByte() &&
                bytes[end - 1] == 1.toByte()
            ) {
                end -= 3
            }
        }
        if (start < end) nals.add(bytes.copyOfRange(start, end))
    }
    return nals
}

fun avcDecoderConfigurationRecord(sps: ByteArray, pps: ByteArray): ByteArray {
    val out = ByteArray(11 + sps.size + pps.size)
    out[0] = 1
    out[1] = if (sps.size > 1) sps[1] else 0
    out[2] = if (sps.size > 2) sps[2] else 0
    out[3] = if (sps.size > 3) sps[3] else 0
    out[4] = 0xFF.toByte()
    out[5] = 0xE1.toByte()
    out[6] = (sps.size ushr 8).toByte()
    out[7] = sps.size.toByte()
    sps.copyInto(out, 8)
    val ppsAt = 8 + sps.size
    out[ppsAt] = 1
    out[ppsAt + 1] = (pps.size ushr 8).toByte()
    out[ppsAt + 2] = pps.size.toByte()
    pps.copyInto(out, ppsAt + 3)
    return out
}

fun lengthPrefixed(nals: List<ByteArray>): ByteArray {
    var size = 0
    for (nal in nals) size += 4 + nal.size
    val out = ByteArray(size)
    var offset = 0
    for (nal in nals) {
        val len = nal.size
        out[offset] = (len ushr 24).toByte()
        out[offset + 1] = (len ushr 16).toByte()
        out[offset + 2] = (len ushr 8).toByte()
        out[offset + 3] = len.toByte()
        nal.copyInto(out, offset + 4)
        offset += 4 + len
    }
    return out
}

/** SPS/PPS become `csd-0`. VCL NALs (types 1 and 5) become a length-prefixed sample. */
fun avcAccessUnit(annexB: ByteArray): AvcUnit? {
    val nals = annexBNals(annexB)
    if (nals.isEmpty()) return null
    var sps: ByteArray? = null
    var pps: ByteArray? = null
    val vcl = ArrayList<ByteArray>()
    var keyframe = false
    for (nal in nals) {
        if (nal.isEmpty()) continue
        when (nal[0].toInt() and 0x1f) {
            7 -> sps = nal
            8 -> pps = nal
            5 -> {
                keyframe = true
                vcl.add(nal)
            }
            1 -> vcl.add(nal)
        }
    }
    if (vcl.isEmpty()) return null
    val config = if (sps != null && pps != null) avcDecoderConfigurationRecord(sps, pps) else null
    return AvcUnit(config, lengthPrefixed(vcl), keyframe)
}

fun isSoftwareAvcDecoder(name: String): Boolean {
    val normalized = name.lowercase()
    return normalized.startsWith("omx.google.") || normalized.startsWith("c2.android.")
}

/** Prefer a non-software AVC decoder. Names come from MediaCodecList. */
fun preferAvcDecoder(names: List<String>): String? {
    val decoders = names.filter { name ->
        val normalized = name.lowercase()
        normalized.contains("avc") || normalized.contains("h264") || normalized.contains("h.264")
    }
    return decoders.firstOrNull { !isSoftwareAvcDecoder(it) } ?: decoders.firstOrNull()
}

fun remotePixel(norm: Float, extent: Int): Int {
    if (extent <= 1) return 0
    return (norm * extent).roundToInt().coerceIn(0, extent - 1)
}

fun liveMouse(action: String, x: Int, y: Int, button: String = "left"): String {
    return JSONObject()
        .put("type", "mouse")
        .put("action", action)
        .put("x", x)
        .put("y", y)
        .put("button", button)
        .toString()
}

/**
 * Browser-shaped input for the WebRTC `input` channel.
 * An empty list means the caller should keep using `inject_input` (global Android keys).
 */
fun liveControlMessages(
    kind: String,
    width: Int,
    height: Int,
    x: Float = 0f,
    y: Float = 0f,
    x2: Float = 0f,
    y2: Float = 0f,
    text: String = "",
    name: String = "",
    dx: Float = 0f,
    dy: Float = 0f,
): List<String> {
    return when (kind) {
        "tap" -> {
            val px = remotePixel(x, width)
            val py = remotePixel(y, height)
            listOf(liveMouse("down", px, py), liveMouse("up", px, py))
        }
        "right_click" -> {
            val px = remotePixel(x, width)
            val py = remotePixel(y, height)
            listOf(liveMouse("down", px, py, "right"), liveMouse("up", px, py, "right"))
        }
        "scroll" -> {
            val px = remotePixel(x, width)
            val py = remotePixel(y, height)
            listOf(
                JSONObject()
                    .put("type", "wheel")
                    .put("x", px)
                    .put("y", py)
                    .put("dx", dx.toDouble())
                    .put("dy", dy.toDouble())
                    .toString(),
            )
        }
        "swipe" -> {
            val ax = remotePixel(x, width)
            val ay = remotePixel(y, height)
            val bx = remotePixel(x2, width)
            val by = remotePixel(y2, height)
            listOf(liveMouse("down", ax, ay), liveMouse("move", bx, by), liveMouse("up", bx, by))
        }
        "type" -> listOf(JSONObject().put("type", "type").put("text", text).toString())
        "key" -> listOf(JSONObject().put("type", "key").put("keys", name).toString())
        else -> emptyList()
    }
}

/** Connection loss and a refused offer do not get a second attempt. A blip does. */
fun liveFailureShouldRetry(message: String): Boolean {
    val text = message.lowercase()
    val fatal = listOf(
        "fallback screenshot",
        "not available",
        "unavailable",
        "denied",
        "not allowed",
    )
    return fatal.none { text.contains(it) }
}

fun liveFailureNote(message: String, screenshots: Boolean): String {
    val text = message.lowercase()
    val unavailable = text.contains("not available") ||
        text.contains("unavailable") ||
        text.contains("fallback screenshot")
    return when {
        unavailable && screenshots -> "Live video is not available. Showing screenshots."
        unavailable -> "Live video is not available, and screenshots are off for this preset."
        screenshots -> "Live video stopped. Showing screenshots."
        else -> message.ifBlank { "Live video stopped." }
    }
}

fun liveStatus(
    codec: String,
    encoder: String,
    hardware: Boolean,
    width: Int,
    height: Int,
    decoder: String,
    loss: Double,
): String {
    val coded = if (encoder.isBlank()) codec.ifBlank { "h264" } else "$codec $encoder"
    val encode = if (hardware) "hw encode" else "sw encode"
    val lossText = if (loss > 0.0) String.format(Locale.US, ", loss %.1f%%", loss * 100) else ""
    return "Live ${width}×${height} · $coded · $encode · $decoder$lossText"
}
