package app.agentlink.node

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import app.agentlink.model.SafGuest
import app.agentlink.model.parseSafGuest
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

class SafStore(private val context: Context) {
    private val prefs = context.getSharedPreferences("agentlink_saf", Context.MODE_PRIVATE)

    fun remember(uri: Uri): String {
        val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        try {
            context.contentResolver.takePersistableUriPermission(uri, flags)
        } catch (_: SecurityException) {
            // The picker grant is still valid for this process.
        }
        val id = idFor(uri)
        prefs.edit().putString(id, uri.toString()).apply()
        return id
    }

    fun roots(): List<Pair<String, String>> {
        return prefs.all.mapNotNull { (id, value) ->
            val raw = value as? String ?: return@mapNotNull null
            id to raw
        }.sortedBy { it.first }
    }

    fun stat(guest: String): JSONObject {
        val parsed = parse(guest)
        val doc = requireDoc(parsed)
        return statJson(
            guest,
            doc.isDirectory,
            doc.isFile,
            doc.length(),
            doc.lastModified(),
            !doc.canWrite(),
        )
    }

    fun list(guest: String): JSONArray {
        val doc = requireDoc(parse(guest))
        if (!doc.isDirectory) error("not a directory")
        val out = JSONArray()
        for (child in doc.listFiles()) {
            out.put(
                entryJson(
                    child.name ?: "",
                    child.isDirectory,
                    child.isFile,
                    child.length(),
                    child.lastModified(),
                ),
            )
        }
        return out
    }

    fun read(guest: String, offset: Long, maxBytes: Int): JSONObject {
        val doc = requireDoc(parse(guest))
        if (!doc.isFile) error("not a file")
        val data = context.contentResolver.openInputStream(doc.uri)?.use { input ->
            if (offset > 0) input.skip(offset)
            val buf = ByteArray(maxBytes.coerceIn(1, 64 * 1024))
            val n = input.read(buf)
            if (n <= 0) ByteArray(0) else buf.copyOf(n)
        } ?: error("could not open $guest")
        val eof = data.size < maxBytes
        return JSONObject().put("data_b64", b64(data)).put("eof", eof)
    }

    fun write(guest: String, offset: Long, data: ByteArray, truncate: Boolean) {
        val parsed = parse(guest)
        if (parsed.relative.isEmpty()) error("refusing to overwrite a folder root")
        val file = ensureFile(parsed)
        if (offset == 0L) {
            val mode = if (truncate) "wt" else "wa"
            context.contentResolver.openOutputStream(file.uri, mode)?.use { it.write(data) }
                ?: error("could not write $guest")
            return
        }
        val existing = context.contentResolver.openInputStream(file.uri)?.use { it.readBytes() }
            ?: ByteArray(0)
        if (existing.size > 8 * 1024 * 1024) error("SAF rewrite above 8 MiB; use the fast path")
        val merged = existing.copyOf(maxOf(existing.size, (offset + data.size).toInt()))
        data.copyInto(merged, offset.toInt())
        context.contentResolver.openOutputStream(file.uri, "wt")?.use { it.write(merged) }
            ?: error("could not write $guest")
    }

    fun mkdir(guest: String, recursive: Boolean) {
        val parsed = parse(guest)
        if (parsed.relative.isEmpty()) return
        val parts = parsed.relative.split('/')
        var parent = tree(parsed.id) ?: error("folder grant is gone")
        parts.forEachIndexed { index, part ->
            val next = parent.findFile(part)
            parent = when {
                next != null && next.isDirectory -> next
                next != null -> error("$part exists and is not a directory")
                index == parts.lastIndex || recursive -> parent.createDirectory(part)
                    ?: error("could not create $part")
                else -> error("missing parent")
            }
        }
    }

    fun remove(guest: String, recursive: Boolean) {
        val doc = requireDoc(parse(guest))
        if (doc.isDirectory && doc.listFiles().isNotEmpty() && !recursive) {
            error("directory is not empty")
        }
        if (!deleteRec(doc)) error("could not remove $guest")
    }

    fun rename(from: String, to: String) {
        val src = parse(from)
        val dst = parse(to)
        if (src.id != dst.id) error("SAF rename must stay in the same folder grant")
        val srcParent = src.relative.substringBeforeLast('/', "")
        val dstParent = dst.relative.substringBeforeLast('/', "")
        if (srcParent != dstParent) error("cross-directory SAF rename is not supported")
        val name = dst.relative.substringAfterLast('/')
        if (name.isEmpty()) error("missing destination name")
        val doc = requireDoc(src)
        if (!doc.renameTo(name)) error("provider rejected the rename")
    }

    fun stage(guest: String, write: Boolean, cacheDir: File): File {
        val parsed = parse(guest)
        if (parsed.relative.isEmpty()) error("stage a file inside the folder, not the root")
        val dest = File(cacheDir, "saf-stage/${parsed.id}/${parsed.relative}")
        if (dest.canonicalPath.startsWith(cacheDir.canonicalPath).not()) {
            error("staged path escapes the cache")
        }
        dest.parentFile?.mkdirs()
        if (!write) {
            val doc = requireDoc(parsed)
            if (!doc.isFile) error("only files can be staged")
            context.contentResolver.openInputStream(doc.uri)?.use { input ->
                dest.outputStream().use { input.copyTo(it) }
            } ?: error("could not stage $guest")
        } else if (!dest.exists()) {
            dest.createNewFile()
        }
        return dest
    }

    fun publish(guest: String, realPath: String) {
        val real = File(realPath)
        val file = ensureFile(parse(guest))
        context.contentResolver.openOutputStream(file.uri, "wt")?.use { out ->
            real.inputStream().use { it.copyTo(out) }
        } ?: error("could not publish $guest")
    }

    private fun parse(guest: String): SafGuest =
        parseSafGuest(guest) ?: error("not a saf path")

    private fun uriOf(id: String): Uri? = prefs.getString(id, null)?.let(Uri::parse)

    private fun tree(id: String): DocumentFile? {
        val uri = uriOf(id) ?: return null
        return DocumentFile.fromTreeUri(context, uri)
    }

    private fun requireDoc(guest: SafGuest): DocumentFile {
        var doc = tree(guest.id) ?: error("folder grant is gone")
        if (guest.relative.isEmpty()) return doc
        for (part in guest.relative.split('/')) {
            doc = doc.findFile(part) ?: error("missing ${guest.relative}")
        }
        return doc
    }

    private fun ensureFile(guest: SafGuest): DocumentFile {
        val name = guest.relative.substringAfterLast('/')
        val parentRel = guest.relative.substringBeforeLast('/', "")
        val parent = if (parentRel.isEmpty()) {
            tree(guest.id) ?: error("folder grant is gone")
        } else {
            requireDoc(guest.copy(relative = parentRel))
        }
        if (!parent.isDirectory) error("parent is not a directory")
        parent.findFile(name)?.let { return it }
        return parent.createFile("application/octet-stream", name) ?: error("could not create $name")
    }

    private fun deleteRec(doc: DocumentFile): Boolean {
        if (doc.isDirectory) {
            for (child in doc.listFiles()) deleteRec(child)
        }
        return doc.delete()
    }

    private fun idFor(uri: Uri): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(uri.toString().toByteArray())
        return digest.take(6).joinToString("") { "%02x".format(it) }
    }
}
