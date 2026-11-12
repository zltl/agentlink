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
        val id = shells.open("exec", payload, allowShizuku = false, allowRoot = false)
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
        // Owner is allowed; in-process cleanup (null caller) still closes.
        shells.resize(id, "bob")
        shells.close(id, "bob")
    }
}
