package app.agentlink.node

import android.content.Context
import android.os.Build
import android.util.DisplayMetrics
import android.view.WindowManager
import app.agentlink.BuildConfig
import org.json.JSONArray
import org.json.JSONObject
import uniffi.agentlink_ffi.NodeHost
import java.io.File

class AndroidHost(
    private val context: Context,
    private val saf: SafStore,
    private val shells: ShellSessions,
    private val capture: ScreenGrabber,
    private val allowShizuku: Boolean,
    private val allowRoot: Boolean,
    private val onStatus: (String) -> Unit,
) : NodeHost {
    override fun unary(kind: String, payloadJson: String): String = guard {
        val payload = jsonObject(payloadJson)
        when (kind) {
            "device_info" -> hostOk(deviceInfo())
            "stat" -> hostOk(saf.stat(payload.getString("path")))
            "list_dir" -> hostOk(saf.list(payload.getString("path")))
            "read_file" -> hostOk(
                saf.read(
                    payload.getString("path"),
                    payload.optLong("offset"),
                    payload.optInt("max_bytes", 64 * 1024),
                ),
            )
            "write_file" -> {
                val data = unb64(payload.optString("data_b64"))
                saf.write(
                    payload.getString("path"),
                    payload.optLong("offset"),
                    data,
                    payload.optBoolean("truncate", true),
                )
                hostOk(JSONObject().put("bytes", data.size))
            }
            "mkdir" -> {
                saf.mkdir(payload.getString("path"), payload.optBoolean("recursive"))
                hostOk(JSONObject())
            }
            "remove" -> {
                saf.remove(payload.getString("path"), payload.optBoolean("recursive"))
                hostOk(JSONObject())
            }
            "rename" -> {
                saf.rename(payload.getString("from"), payload.getString("to"))
                hostOk(JSONObject())
            }
            "pty_resize" -> {
                shells.resize(payload.optString("session_id"))
                hostOk(JSONObject())
            }
            "extension" -> hostOk(extension(payload.getString("name"), payload.optJSONObject("payload") ?: JSONObject()))
            else -> hostErr("unknown host call $kind")
        }
    }

    override fun openSession(kind: String, payloadJson: String): String = guard {
        val id = shells.open(kind, jsonObject(payloadJson), allowShizuku, allowRoot)
        hostOk(JSONObject().put("session_id", id))
    }

    override fun pollSession(sessionId: String): String = guard {
        hostOk(shells.poll(sessionId))
    }

    override fun sessionInput(sessionId: String, dataB64: String): String = guard {
        val data = unb64(dataB64)
        shells.input(sessionId, data)
        hostOk(JSONObject().put("bytes", data.size))
    }

    override fun closeSession(sessionId: String): String = guard {
        shells.close(sessionId)
        hostOk(JSONObject().put("closed", sessionId))
    }

    override fun preparePath(guest: String, write: Boolean): String = guard {
        val real = saf.stage(guest, write, context.cacheDir)
        hostOk(JSONObject().put("real_path", real.absolutePath))
    }

    override fun publishPath(guest: String, realPath: String): String = guard {
        saf.publish(guest, realPath)
        hostOk(JSONObject())
    }

    override fun onStatus(statusJson: String) {
        onStatus(statusJson)
    }

    private fun extension(name: String, payload: JSONObject): JSONObject {
        return when (name) {
            "screenshot" -> screenshot(payload)
            "inject_input" -> inject(payload)
            "webrtc_signal" -> JSONObject()
                .put("status", "unavailable")
                .put("fallback", "screenshot")
                .put("reason", "this phone does not encode live video")
                // Clipped session grant from the relay (_allow_control). The
                // web viewer needs this to settle Take control over JPEG.
                .put("control", payload.optBoolean("_allow_control", false))
            else -> throw IllegalArgumentException("extension $name is not enabled")
        }
    }

    private fun screenshot(payload: JSONObject): JSONObject {
        if (!capture.active) {
            throw IllegalStateException("screen capture is not granted; open agentlink and allow it again")
        }
        val quality = payload.optInt("quality", 55)
        var frame = capture.jpeg(quality)
        if (frame == null) {
            Thread.sleep(80)
            frame = capture.jpeg(quality)
        }
        val shot = frame ?: throw IllegalStateException("no screenshot frame yet")
        if (shot.bytes.size > 4_000_000) {
            throw IllegalStateException("screenshot is too large")
        }
        return JSONObject()
            .put("mime", "image/jpeg")
            .put("width", shot.width)
            .put("height", shot.height)
            .put("data_b64", b64(shot.bytes))
    }

    private fun inject(payload: JSONObject): JSONObject {
        val service = AgentAccessibilityService.instance
            ?: throw IllegalStateException("accessibility service is not enabled")
        val action = payload.optString("action")
        val metrics = realMetrics()
        // Accept the desktop/web inject_input vocabulary (click/move/scroll/keys)
        // so Take control over JPEG from the dashboard can drive this phone.
        val ok = when (action) {
            "tap", "click" -> service.tap(px(payload.optDouble("x"), metrics.widthPixels), px(payload.optDouble("y"), metrics.heightPixels))
            "move" -> true
            "scroll" -> {
                // Prefer explicit coords; otherwise swipe from screen center so a
                // CLI/MCP scroll without x/y does not start at (0,0).
                val x = if (payload.has("x")) px(payload.optDouble("x"), metrics.widthPixels)
                else metrics.widthPixels / 2f
                val y = if (payload.has("y")) px(payload.optDouble("y"), metrics.heightPixels)
                else metrics.heightPixels / 2f
                val dy = payload.optDouble("dy", 0.0)
                val dx = payload.optDouble("dx", 0.0)
                if (dy == 0.0 && dx == 0.0) true
                else {
                    // Desktop/web send wheel notches/deltas (often |d|<=40 after
                    // clamp). Accessibility needs a real finger travel distance.
                    val unitX = metrics.widthPixels * 0.08f
                    val unitY = metrics.heightPixels * 0.08f
                    val maxX = metrics.widthPixels * 0.45f
                    val maxY = metrics.heightPixels * 0.45f
                    val swipeDx = (dx.toFloat() * unitX).coerceIn(-maxX, maxX)
                    // Positive dy = scroll up on desktop → finger moves down.
                    val swipeDy = (-dy.toFloat() * unitY).coerceIn(-maxY, maxY)
                    service.swipe(x, y, x + swipeDx, y + swipeDy, 280)
                }
            }
            "swipe" -> service.swipe(
                px(payload.optDouble("x"), metrics.widthPixels),
                px(payload.optDouble("y"), metrics.heightPixels),
                px(payload.optDouble("x2"), metrics.widthPixels),
                px(payload.optDouble("y2"), metrics.heightPixels),
                payload.optLong("duration_ms", 280),
            )
            "type" -> service.typeText(payload.optString("text"))
            "key" -> {
                if (payload.has("down") && !payload.optBoolean("down", true)) true
                else {
                    val name = payload.optString("name").ifBlank { payload.optString("keys") }
                    service.key(name)
                }
            }
            "global" -> service.global(payload.optString("name"))
            "click_element" -> service.clickElement(
                payload.optString("text").ifBlank { null },
                payload.optString("id").ifBlank { null },
            )
            "tree" -> return service.tree()
            else -> throw IllegalArgumentException("unknown input action $action")
        }
        if (!ok) throw IllegalStateException("input action $action did not apply")
        return JSONObject().put("action", action).put("ok", true)
    }

    private fun deviceInfo(): JSONObject {
        val safRoots = JSONArray()
        for ((id, uri) in saf.roots()) {
            safRoots.put(JSONObject().put("id", id).put("uri", uri))
        }
        return JSONObject()
            .put("manufacturer", Build.MANUFACTURER)
            .put("model", Build.MODEL)
            .put("device", Build.DEVICE)
            .put("sdk_int", Build.VERSION.SDK_INT)
            .put("release", Build.VERSION.RELEASE)
            .put("abis", JSONArray(Build.SUPPORTED_ABIS.toList()))
            .put("app_version", BuildConfig.VERSION_NAME)
            .put("shizuku", allowShizuku && shizukuReady())
            .put("root_opt_in", allowRoot)
            .put("screen_capture", capture.active)
            .put("accessibility", AgentAccessibilityService.instance != null)
            .put("saf_roots", safRoots)
    }

    private fun realMetrics(): DisplayMetrics {
        val metrics = DisplayMetrics()
        @Suppress("DEPRECATION")
        context.getSystemService(WindowManager::class.java).defaultDisplay.getRealMetrics(metrics)
        return metrics
    }

    private fun px(fraction: Double, span: Int): Float {
        return (fraction.coerceIn(0.0, 1.0) * span).toFloat()
    }

    private fun guard(block: () -> String): String {
        return try {
            block()
        } catch (err: Throwable) {
            hostErr(err.message ?: err.javaClass.simpleName)
        }
    }
}

fun appendAudit(file: File, line: String) {
    file.parentFile?.mkdirs()
    file.appendText(line + "\n")
}
