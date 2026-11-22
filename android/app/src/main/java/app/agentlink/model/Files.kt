package app.agentlink.model

import org.json.JSONObject

data class DirItem(val name: String, val isDir: Boolean)

data class SafGuest(val id: String, val relative: String)

fun defaultRootPath(os: String): String {
    val lower = os.trim().lowercase()
    return when {
        "android" in lower -> "app:/"
        "darwin" in lower || "mac" in lower -> "/"
        lower.startsWith("win") -> "C:/"
        else -> "/"
    }
}

fun defaultTransferPath(os: String): String {
    val lower = os.trim().lowercase()
    return when {
        "android" in lower -> "app:/files/from-phone.bin"
        "darwin" in lower || "mac" in lower -> "/tmp/from-phone.bin"
        lower.startsWith("win") -> "C:/Users/Public/from-phone.bin"
        else -> "/tmp/from-phone.bin"
    }
}

fun childPath(parent: String, name: String): String {
    val base = if (parent.endsWith("/")) parent.dropLast(1) else parent
    return "$base/$name"
}

fun parentPath(path: String): String? {
    val normalized = path.trim().replace('\\', '/')
    if (normalized.isEmpty() || normalized == "/") return null
    val trimmed = normalized.trimEnd('/')
    if (trimmed.isEmpty()) return null
    val slash = trimmed.lastIndexOf('/')
    if (slash < 0) return null
    if (slash == 0) return "/"
    val parent = trimmed.substring(0, slash)
    return if (parent.endsWith(":")) "$parent/" else parent
}

fun searchFiles(
    root: String,
    query: String,
    maxDepth: Int = 4,
    maxHits: Int = 200,
    list: (String) -> List<DirItem>,
): List<String> {
    val needle = query.trim()
    if (needle.isEmpty() || maxHits <= 0) return emptyList()
    val hits = mutableListOf<String>()
    fun walk(path: String, depth: Int) {
        if (hits.size >= maxHits || depth > maxDepth) return
        val entries = try {
            list(path)
        } catch (_: Exception) {
            return
        }
        for (entry in entries) {
            if (hits.size >= maxHits) return
            val child = childPath(path, entry.name)
            if (entry.name.contains(needle, ignoreCase = true)) hits += child
            if (entry.isDir) walk(child, depth + 1)
        }
    }
    walk(root, 0)
    return hits
}

fun parseSafGuest(guest: String): SafGuest? {
    val path = guest.trim().trimEnd('/')
    if (!path.startsWith("saf:/")) return null
    val rest = path.removePrefix("saf:/")
    if (rest.isEmpty() || rest.split('/').any { it == ".." || it == "." || it.isEmpty() }) {
        return null
    }
    val slash = rest.indexOf('/')
    return if (slash < 0) {
        SafGuest(rest, "")
    } else {
        SafGuest(rest.substring(0, slash), rest.substring(slash + 1))
    }
}

fun looksTextual(bytes: ByteArray): Boolean = bytes.none { it == 0.toByte() }

fun relayProblem(url: String): String? {
    val trimmed = url.trim()
    if (!trimmed.startsWith("wss://")) {
        return "Relay URL must start with wss://"
    }
    if (trimmed.length < "wss://x".length) {
        return "Relay URL is incomplete"
    }
    return null
}

fun fingerprintProblem(value: String): String? {
    val trimmed = value.trim()
    if (trimmed.isEmpty()) return null
    val parts = trimmed.split('+').map { it.trim() }.filter { it.isNotEmpty() }
    val ok = parts.isNotEmpty() && parts.all { trustTokenOk(it) }
    return if (ok) null else "Fingerprint must be sha256: and 64 hex characters, or system / webpki"
}

private fun trustTokenOk(token: String): Boolean {
    val lower = token.lowercase()
    if (lower == "system" || lower == "webpki" || lower == "web-pki") return true
    val hex = when {
        lower.startsWith("intermediate:sha256:") -> lower.removePrefix("intermediate:sha256:")
        lower.startsWith("spki:sha256:") -> lower.removePrefix("spki:sha256:")
        lower.startsWith("sha256:") -> lower.removePrefix("sha256:")
        else -> return false
    }
    return hex.length == 64 && hex.all { it in '0'..'9' || it in 'a'..'f' }
}

fun shellQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

fun shellJoin(program: String, args: List<String>): String =
    (listOf(program) + args).joinToString(" ") { shellQuote(it) }

data class ShellPlan(val argv: List<String>, val via: String)

fun planCommand(program: String, args: List<String>, shell: Boolean, shizuku: Boolean, root: Boolean): ShellPlan {
    // When shell=true with no separate args, `program` is already a raw shell
    // command line (e.g. "echo hi && ls") and must not be single-quoted.
    val command = if (shell && args.isEmpty()) program else shellJoin(program, args)
    return when {
        root -> ShellPlan(listOf("su", "-c", command), "root")
        shizuku && shell -> ShellPlan(listOf("/system/bin/sh", "-c", command), "shizuku")
        shizuku -> ShellPlan(listOf(program) + args, "shizuku")
        shell -> ShellPlan(listOf("/system/bin/sh", "-c", command), "shell")
        else -> ShellPlan(listOf(program) + args, "exec")
    }
}

fun jsonString(value: String): String {
    val out = StringBuilder(value.length + 2)
    out.append('"')
    for (ch in value) {
        when (ch) {
            '\\' -> out.append("\\\\")
            '"' -> out.append("\\\"")
            '\n' -> out.append("\\n")
            '\r' -> out.append("\\r")
            '\t' -> out.append("\\t")
            else -> if (ch.code < 0x20) out.append("\\u%04x".format(ch.code)) else out.append(ch)
        }
    }
    out.append('"')
    return out.toString()
}

fun auditRecord(
    ts: String,
    op: String,
    detail: String,
    ok: Boolean,
    error: String? = null,
    peer: String? = null,
): String {
    val out = StringBuilder()
    out.append("{\"ts\":").append(jsonString(ts))
    out.append(",\"op\":").append(jsonString(op))
    out.append(",\"detail\":").append(jsonString(detail))
    out.append(",\"ok\":").append(if (ok) "true" else "false")
    if (error != null) out.append(",\"error\":").append(jsonString(error))
    if (peer != null) out.append(",\"peer\":").append(jsonString(peer))
    out.append('}')
    return out.toString()
}

private val hasRealOrgJson: Boolean by lazy {
    try {
        JSONObject("{\"a\":\"b\"}").opt("a") == "b"
    } catch (_: Throwable) {
        false
    }
}

fun jsonField(json: String, key: String): String? {
    if (hasRealOrgJson) {
        return try {
            val obj = JSONObject(json)
            if (!obj.has(key) || obj.isNull(key)) return null
            obj.opt(key) as? String
        } catch (_: Throwable) {
            null
        }
    }
    return parseTopLevelJsonStringField(json, key)
}

private fun parseTopLevelJsonStringField(json: String, targetKey: String): String? {
    var i = 0
    val n = json.length
    fun skipWs() {
        while (i < n && json[i] in " \t\r\n") i++
    }
    fun readString(): String? {
        if (i >= n || json[i] != '"') return null
        i++
        val sb = StringBuilder()
        while (i < n) {
            val ch = json[i++]
            when (ch) {
                '"' -> return sb.toString()
                '\\' -> {
                    if (i >= n) return null
                    when (val esc = json[i++]) {
                        '"', '\\', '/' -> sb.append(esc)
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            if (i + 4 > n) return null
                            val hex = json.substring(i, i + 4).toIntOrNull(16) ?: return null
                            sb.append(hex.toChar())
                            i += 4
                        }
                        else -> return null
                    }
                }
                else -> {
                    if (ch.code < 0x20) return null
                    sb.append(ch)
                }
            }
        }
        return null
    }
    fun skipValue(): Boolean {
        skipWs()
        if (i >= n) return false
        return when (json[i]) {
            '"' -> readString() != null
            '{' -> {
                i++
                skipWs()
                if (i < n && json[i] == '}') {
                    i++
                    return true
                }
                while (i < n) {
                    skipWs()
                    if (readString() == null) return false
                    skipWs()
                    if (i >= n || json[i] != ':') return false
                    i++
                    if (!skipValue()) return false
                    skipWs()
                    if (i >= n) return false
                    when (json[i++]) {
                        ',' -> continue
                        '}' -> return true
                        else -> return false
                    }
                }
                false
            }
            '[' -> {
                i++
                skipWs()
                if (i < n && json[i] == ']') {
                    i++
                    return true
                }
                while (i < n) {
                    if (!skipValue()) return false
                    skipWs()
                    if (i >= n) return false
                    when (json[i++]) {
                        ',' -> continue
                        ']' -> return true
                        else -> return false
                    }
                }
                false
            }
            else -> {
                val start = i
                while (i < n && json[i] !in ",}] \t\r\n") i++
                i > start
            }
        }
    }
    skipWs()
    if (i >= n || json[i] != '{') return null
    i++
    skipWs()
    if (i < n && json[i] == '}') return null
    while (i < n) {
        skipWs()
        val k = readString() ?: return null
        skipWs()
        if (i >= n || json[i] != ':') return null
        i++
        skipWs()
        if (k == targetKey) {
            return if (i < n && json[i] == '"') readString() else null
        }
        if (!skipValue()) return null
        skipWs()
        if (i >= n) return null
        when (json[i++]) {
            ',' -> continue
            '}' -> return null
            else -> return null
        }
    }
    return null
}

fun webrtcFallsBackToScreenshot(body: String): Boolean {
    return jsonField(body, "status") == "unavailable" && jsonField(body, "fallback") == "screenshot"
}
