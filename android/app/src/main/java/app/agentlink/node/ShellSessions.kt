package app.agentlink.node

import android.content.pm.PackageManager
import app.agentlink.model.planCommand
import org.json.JSONObject
import rikka.shizuku.Shizuku
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread

class ShellSessions {
    private val sessions = ConcurrentHashMap<String, Running>()

    fun open(kind: String, payload: JSONObject, allowShizuku: Boolean, allowRoot: Boolean): String {
        val id = payload.optString("session_id").ifBlank { java.util.UUID.randomUUID().toString() }
        val cwd = payload.optString("cwd").ifBlank { null }
        val env = envPairs(payload.optJSONArray("env"))
        val plan = when (kind) {
            "pty" -> {
                val command = payload.optString("command").ifBlank { null }
                if (command == null) {
                    planCommand("/system/bin/sh", emptyList(), shell = false, shizuku = allowShizuku && shizukuReady(), root = false)
                } else {
                    planCommand(command, emptyList(), shell = true, shizuku = allowShizuku && shizukuReady(), root = allowRoot)
                }
            }
            else -> {
                val program = payload.optString("program")
                if (program.isBlank()) error("command is empty")
                val args = mutableListOf<String>()
                val raw = payload.optJSONArray("args")
                if (raw != null) {
                    for (i in 0 until raw.length()) args += raw.optString(i)
                }
                val useShizuku = allowShizuku && shizukuReady() && !allowRoot
                planCommand(
                    program,
                    args,
                    shell = payload.optBoolean("shell"),
                    shizuku = useShizuku,
                    root = allowRoot,
                )
            }
        }
        val argv = rootWithCwd(plan.argv, plan.via, cwd)
        val process = start(argv, env, if (plan.via == "root") null else cwd, plan.via)
        val stream = if (kind == "pty") "pty" else "stdout"
        val running = Running(process, stream)
        sessions[id] = running
        running.pump()
        return id
    }

    fun poll(id: String): JSONObject {
        val running = sessions[id] ?: return JSONObject().put("event", "exit").put("code", -1)
        return running.poll()
    }

    fun input(id: String, data: ByteArray) {
        val running = sessions[id] ?: error("shell session is gone")
        running.process.outputStream.write(data)
        running.process.outputStream.flush()
    }

    fun close(id: String) {
        sessions.remove(id)?.process?.destroy()
    }

    fun resize(@Suppress("UNUSED_PARAMETER") id: String) {
        // One-shot exec is a pipe. Interactive shells use the Rust PTY, which
        // honors TIOCSWINSZ, and do not come through this map.
    }

    private fun start(argv: List<String>, env: Map<String, String>, cwd: String?, via: String): Process {
        if (via == "shizuku") {
            val envp = env.entries.map { "${it.key}=${it.value}" }.toTypedArray()
            return shizukuProcess(argv.toTypedArray(), envp.takeIf { it.isNotEmpty() }, cwd)
        }
        val builder = ProcessBuilder(argv)
        if (!cwd.isNullOrBlank()) builder.directory(File(cwd))
        if (env.isNotEmpty()) builder.environment().putAll(env)
        builder.redirectErrorStream(false)
        return builder.start()
    }

    private fun rootWithCwd(argv: List<String>, via: String, cwd: String?): List<String> {
        if (via != "root" || cwd.isNullOrBlank() || argv.size < 3) return argv
        val quoted = app.agentlink.model.shellQuote(cwd)
        return listOf(argv[0], argv[1], "cd $quoted && ${argv[2]}")
    }

    private class Running(val process: Process, private val stdoutName: String) {
        private val events = ArrayDeque<JSONObject>()
        private val lock = Any()
        private var exitCode: Int? = null

        fun pump() {
            thread(name = "agentlink-stdout", isDaemon = true) { drain(process.inputStream, stdoutName) }
            thread(name = "agentlink-stderr", isDaemon = true) { drain(process.errorStream, "stderr") }
            thread(name = "agentlink-wait", isDaemon = true) {
                val code = try {
                    process.waitFor()
                } catch (_: InterruptedException) {
                    -1
                }
                synchronized(lock) { exitCode = code }
            }
        }

        fun poll(): JSONObject {
            synchronized(lock) {
                events.poll()?.let { return it }
                val code = exitCode
                if (code != null) {
                    return JSONObject().put("event", "exit").put("code", code)
                }
                return JSONObject().put("event", "pending")
            }
        }

        private fun drain(stream: InputStream, name: String) {
            val buf = ByteArray(16 * 1024)
            try {
                while (true) {
                    val n = stream.read(buf)
                    if (n < 0) break
                    if (n == 0) continue
                    val event = JSONObject()
                        .put("event", "chunk")
                        .put("stream", name)
                        .put("data_b64", b64(buf.copyOf(n)))
                    synchronized(lock) { events.add(event) }
                }
            } catch (_: IOException) {
                // The process closed the pipe.
            }
        }
    }
}

private fun shizukuProcess(argv: Array<String>, env: Array<String>?, cwd: String?): Process {
    // Shizuku 13 keeps newProcess private. It is still the supported way to
    // spawn a process; the public surface is the user-service binder.
    val method = Shizuku::class.java.getDeclaredMethod(
        "newProcess",
        Array<String>::class.java,
        Array<String>::class.java,
        String::class.java,
    )
    method.isAccessible = true
    return method.invoke(null, argv, env, cwd) as Process
}

fun shizukuReady(): Boolean {
    return try {
        Shizuku.pingBinder() &&
            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
    } catch (_: Throwable) {
        false
    }
}
