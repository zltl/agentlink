package app.agentlink.model

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Base64

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class JoinInputTest {
    private val pin = "sha256:" + "ab".repeat(32)
    private val token = "cd".repeat(32)

    @Test
    fun short_empty_malformed_and_valid_invites() {
        val empty = decodeInvite("").exceptionOrNull()?.message.orEmpty()
        assertTrue(empty.contains("empty"))
        val blank = decodeInvite("   ").exceptionOrNull()?.message.orEmpty()
        assertTrue(blank.contains("empty"))
        assertTrue(parseJoinInput("").getOrNull() is JoinInput.Absent)
        assertTrue(parseJoinInput("   ").getOrNull() is JoinInput.Absent)

        val short = parseJoinInput("123").exceptionOrNull()?.message.orEmpty()
        assertTrue(short.contains("too short"))
        assertTrue(decodeInvite("123").isFailure)
        val refused = resolveJoin("wss://relay.example:7443", "system", "123", "phone")
        assertTrue(refused.isFailure)
        assertTrue(refused.exceptionOrNull()?.message.orEmpty().contains("too short"))

        for (damaged in listOf(
            "agentlink-invite:v1:",
            "agentlink-invite:v1:%%%",
            "agentlink-invite:v1:123",
            "agentlink-invite:v2:aaaa",
        )) {
            val err = parseJoinInput(damaged).exceptionOrNull()?.message.orEmpty()
            assertTrue("$damaged -> $err", err.contains("damaged") || err.contains("must start with"))
            assertTrue(decodeInvite(damaged).isFailure)
        }

        val envelope = JSONObject()
            .put("relay", "wss://relay.example.com")
            .put("fingerprint", pin)
            .put("token", "123")
            .put("name", "phone")
        val shortToken = INVITE_PREFIX + Base64.getUrlEncoder().withoutPadding()
            .encodeToString(envelope.toString().toByteArray())
        val tokenErr = decodeInvite(shortToken).exceptionOrNull()?.message.orEmpty()
        assertTrue(tokenErr.contains("not a one-time token"))

        val weak = JSONObject()
            .put("relay", "wss://relay.example.com")
            .put("fingerprint", "sha256:ab")
            .put("token", token)
            .put("name", "phone")
        val weakText = INVITE_PREFIX + Base64.getUrlEncoder().withoutPadding()
            .encodeToString(weak.toString().toByteArray())
        val weakErr = decodeInvite(weakText).exceptionOrNull()?.message.orEmpty()
        assertTrue(weakErr.contains("certificate trust"))

        val valid = JSONObject()
            .put("relay", "https://relay.example.com")
            .put("fingerprint", pin)
            .put("trust", "webpki")
            .put("token", token.uppercase())
            .put("name", "phone")
        val text = INVITE_PREFIX + Base64.getUrlEncoder().withoutPadding()
            .encodeToString(valid.toString().toByteArray())
        val decoded = decodeInvite(text).getOrThrow()
        assertEquals("wss://relay.example.com", decoded.relay)
        assertEquals("$pin+webpki", decoded.fingerprint)
        assertEquals(token, decoded.token)
        assertEquals("phone", decoded.name)
        val resolved = resolveJoin("", "", text, "").getOrThrow()
        assertEquals(decoded.relay, resolved.relay)
        assertEquals(decoded.token, resolved.token)
        assertEquals("phone", resolved.name)
        assertNull(resolveJoin("wss://relay.example:7443", "system", "", "phone").exceptionOrNull())
    }
}
