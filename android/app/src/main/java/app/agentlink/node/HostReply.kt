package app.agentlink.node

import org.json.JSONArray
import org.json.JSONObject

fun hostOk(body: Any? = JSONObject()): String {
    return JSONObject().put("ok", true).put("body", body ?: JSONObject.NULL).toString()
}

fun hostErr(message: String): String {
    return JSONObject().put("ok", false).put("error", message).toString()
}

fun jsonObject(raw: String): JSONObject {
    if (raw.isBlank()) return JSONObject()
    return JSONObject(raw)
}

fun b64(bytes: ByteArray): String =
    android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)

fun unb64(text: String): ByteArray =
    android.util.Base64.decode(text, android.util.Base64.DEFAULT)

fun statJson(namePath: String, isDir: Boolean, isFile: Boolean, size: Long, modified: Long, readonly: Boolean): JSONObject {
    return JSONObject()
        .put("path", namePath)
        .put("is_dir", isDir)
        .put("is_file", isFile)
        .put("is_symlink", false)
        .put("size", size)
        .put("modified_unix_ms", modified)
        .put("readonly", readonly)
        .put("mode", JSONObject.NULL)
}

fun entryJson(name: String, isDir: Boolean, isFile: Boolean, size: Long, modified: Long): JSONObject {
    return JSONObject()
        .put("name", name)
        .put("is_dir", isDir)
        .put("is_file", isFile)
        .put("is_symlink", false)
        .put("size", size)
        .put("modified_unix_ms", modified)
        .put("mode", JSONObject.NULL)
}

fun envPairs(array: JSONArray?): Map<String, String> {
    if (array == null) return emptyMap()
    val out = linkedMapOf<String, String>()
    for (i in 0 until array.length()) {
        val pair = array.optJSONArray(i) ?: continue
        val key = pair.optString(0)
        if (key.isNotEmpty()) out[key] = pair.optString(1)
    }
    return out
}
