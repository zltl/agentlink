package app.agentlink.node

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ShellSessionsOwnerTest {
    private fun sleepCommand(): Pair<String, JSONArray> {
        return if (File("/bin/sleep").exists()) {
            "/bin/sleep" to JSONArray().put("30")
        } else {
            "cmd.exe" to JSONArray().put("/c").put("ping").put("-n").put("30").put("127.0.0.1")
        }
    }

    private fun stdinEchoCommand(): Pair<String, JSONArray> {
        return if (File("/bin/cat").exists()) {
            "/bin/cat" to JSONArray()
        } else {
            "cmd.exe" to JSONArray().put("/c").put("findstr").put(".*")
        }
    }

    @Test
    fun input_resize_and_close_require_the_recorded_owner() {
        val shells = ShellSessions()
        val (program, args) = sleepCommand()
        val payload = JSONObject()
            .put("program", program)
            .put("args", args)
            .put("shell", false)
            .put("_owner_peer", "bob")
            .put("release", "release-bob")
        val id = shells.open("exec", payload, allowShizuku = false, allowRoot = false)
        try {
            shells.poll(id, "alice")
            fail("alice must not read bob's session output")
        } catch (err: IllegalStateException) {
            assertTrue(err.message.orEmpty().contains("not found for this peer"))
        }
        try {
            shells.poll(id, "")
            fail("empty caller must not poll")
        } catch (err: IllegalStateException) {
            assertTrue(err.message.orEmpty().contains("not found for this peer"))
        }
        val bobPoll = shells.poll(id, "bob")
        assertTrue(
            bobPoll.optString("event") == "pending"
                || bobPoll.optString("event") == "chunk"
                || bobPoll.optString("event") == "exit"
        )
        try {
            shells.input(id, "x".toByteArray(), "alice")
            fail("alice must not write bob's session")
        } catch (err: IllegalStateException) {
            assertTrue(err.message.orEmpty().contains("not found for this peer"))
        }
        try {
            shells.resize(id, "alice")
            fail("alice must not resize bob's session")
        } catch (err: IllegalStateException) {
            assertTrue(err.message.orEmpty().contains("not found for this peer"))
        }
        try {
            shells.close(id, "alice")
            fail("alice must not close bob's session")
        } catch (err: IllegalStateException) {
            assertTrue(err.message.orEmpty().contains("not found for this peer"))
        }
        // Owner is allowed to close; UUID-only / empty caller is not.
        shells.resize(id, "bob")
        try {
            shells.release(id, "wrong-release")
            fail("forged release must not close bob's session")
        } catch (err: IllegalStateException) {
            assertTrue(err.message.orEmpty().contains("not found for this peer"))
        }
        shells.close(id, "bob")
    }

    @Test
    fun open_without_owner_is_rejected() {
        val shells = ShellSessions()
        val (program, args) = sleepCommand()
        val payload = JSONObject()
            .put("program", program)
            .put("args", args)
            .put("shell", false)
        try {
            shells.open("exec", payload, allowShizuku = false, allowRoot = false)
            fail("open without a recorded owner must fail closed")
        } catch (err: IllegalStateException) {
            assertTrue(err.message.orEmpty().contains("owner is required"))
        }
    }

    @Test
    fun stdin_b64_is_written_closed_and_stdout_drained_before_exit() {
        val shells = ShellSessions()
        val (program, args) = stdinEchoCommand()
        val inputText = "hello-from-stdin\n"
        val payload = JSONObject()
            .put("program", program)
            .put("args", args)
            .put("shell", false)
            .put("stdin_b64", Base64.encodeToString(inputText.toByteArray(), Base64.NO_WRAP))
            .put("_owner_peer", "bob")
            .put("release", "release-stdin")
        val id = shells.open("exec", payload, allowShizuku = false, allowRoot = false)
        val out = StringBuilder()
        var exitCode: Int? = null
        val deadline = System.currentTimeMillis() + 5_000
        while (System.currentTimeMillis() < deadline) {
            val ev = shells.poll(id, "bob")
            when (ev.optString("event")) {
                "chunk" -> {
                    val bytes = Base64.decode(ev.optString("data_b64"), Base64.DEFAULT)
                    out.append(String(bytes))
                }
                "exit" -> {
                    exitCode = ev.optInt("code", -1)
                    break
                }
                else -> Thread.sleep(20)
            }
        }
        shells.close(id, "bob")
        assertEquals("expected clean exit after stdin EOF", 0, exitCode)
        assertTrue("expected echoed stdin before exit, got: $out", out.toString().contains("hello-from-stdin"))
    }

    @Test
    fun closeAll_terminates_active_sessions() {
        val shells = ShellSessions()
        val (program, args) = sleepCommand()
        val payload = JSONObject()
            .put("program", program)
            .put("args", args)
            .put("shell", false)
            .put("_owner_peer", "bob")
            .put("release", "release-all")
        val id = shells.open("exec", payload, allowShizuku = false, allowRoot = false)
        shells.closeAll()
        val after = shells.poll(id, "bob")
        assertEquals("exit", after.optString("event"))
    }
}
