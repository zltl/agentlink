package app.agentlink.node

import org.json.JSONObject
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ShellSessionsOwnerTest {
    @Test
    fun input_resize_and_close_require_the_recorded_owner() {
        val shells = ShellSessions()
        val payload = JSONObject()
            .put("program", "/bin/sleep")
            .put("args", org.json.JSONArray().put("30"))
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
        val payload = JSONObject()
            .put("program", "/bin/sleep")
            .put("args", org.json.JSONArray().put("30"))
            .put("shell", false)
        try {
            shells.open("exec", payload, allowShizuku = false, allowRoot = false)
            fail("open without a recorded owner must fail closed")
        } catch (err: IllegalStateException) {
            assertTrue(err.message.orEmpty().contains("owner is required"))
        }
    }
}
