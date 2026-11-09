package app.agentlink.model

data class DirItem(val name: String, val isDir: Boolean)

data class SafGuest(val id: String, val relative: String)

fun childPath(parent: String, name: String): String {
    val base = if (parent.endsWith("/")) parent.dropLast(1) else parent
    return "$base/$name"
}

fun parentPath(path: String): String? {
    val trimmed = path.trimEnd('/')
    val slash = trimmed.lastIndexOf('/')
    if (slash <= 0) return null
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
    val joined = shellJoin(program, args)
    return when {
        root -> ShellPlan(listOf("su", "-c", joined), "root")
        shizuku && shell -> ShellPlan(listOf("/system/bin/sh", "-c", joined), "shizuku")
        shizuku -> ShellPlan(listOf(program) + args, "shizuku")
        shell -> ShellPlan(listOf("/system/bin/sh", "-c", joined), "shell")
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

fun jsonField(json: String, key: String): String? {
    val needle = "\"$key\""
    val keyAt = json.indexOf(needle)
    if (keyAt < 0) return null
    val colon = json.indexOf(':', keyAt + needle.length)
    if (colon < 0) return null
    var i = colon + 1
    while (i < json.length && json[i].isWhitespace()) i++
    if (i >= json.length || json[i] != '"') return null
    val start = i + 1
    val end = StringBuilder()
    var j = start
    while (j < json.length) {
        val ch = json[j]
        if (ch == '\\' && j + 1 < json.length) {
            end.append(json[j + 1])
            j += 2
            continue
        }
        if (ch == '"') return end.toString()
        end.append(ch)
        j++
    }
    return null
}

fun webrtcFallsBackToScreenshot(body: String): Boolean {
    return jsonField(body, "status") == "unavailable" && jsonField(body, "fallback") == "screenshot"
}
