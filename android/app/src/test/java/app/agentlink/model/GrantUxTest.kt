package app.agentlink.model

import app.agentlink.ui.fatalDesktopMessage
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class GrantUxTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val node = "ab".repeat(32)
    private val key = "cd".repeat(32)
    private val identityDir = "/data/user/0/app.agentlink/files"

    private fun grantJson(
        nodeId: String = node,
        grantee: String = key,
        signature: String = "ff",
    ): String = JSONObject()
        .put("grantee_id", grantee)
        .put("node_id", nodeId)
        .put("nbf_unix", 0)
        .put("exp_unix", 4_102_444_800L)
        .put("jti", "jti-1")
        .put("issuer_id", "ee".repeat(32))
        .put("sig_hex", signature)
        .toString()

    @Test
    fun detectsOnlySignedGrantFailures() {
        assertTrue(isSignedGrantFailure("authentication failed: signed grant required (owner keys configured)"))
        assertTrue(isSignedGrantFailure("SIGNED GRANT REQUIRED"))
        assertFalse(isSignedGrantFailure("grant has expired"))
        assertFalse(isSignedGrantFailure("permission denied: exec"))
        assertFalse(isSignedGrantFailure(null))
    }

    @Test
    fun signedGrantIsFatalForDesktopRetry() {
        assertTrue(fatalDesktopMessage("authentication failed: signed grant required (owner keys configured)"))
    }

    @Test
    fun decoratedTipNamesThisControllersKey() {
        val raw = "authentication failed: signed grant required (owner keys configured); run " +
            "`agentlink grant issue --node $node` (or `agentlink grant refresh --node $node` if a " +
            "grant file still exists)"
        val out = decorateGrantFailure(raw, node, key, identityDir)
        assertTrue(out, out.contains(node))
        assertTrue(out, out.contains(key))
        assertTrue(out, out.contains("--grantee $key"))
        assertTrue(out, out.contains("--policy full --ttl 30d"))
        assertTrue(out, out.contains("--issuer-data-dir <node data dir>"))
        assertTrue(out, out.contains("node service"))
        assertTrue(out, out.contains("checks the signature"))
        assertFalse(out, out.contains("run `agentlink grant issue --node $node`"))
        assertTrue(isGrantFixNote(out))
        assertEquals(out, decorateGrantFailure(out, node, key, identityDir))
    }

    @Test
    fun nodeReportedControllerKeyWinsOverTheLocalKey() {
        val checked = "11".repeat(32)
        val raw = "signed grant required (owner keys configured); the controller public key is $checked"
        val out = decorateGrantFailure(raw, node, key)
        assertTrue(out, out.contains("--grantee $checked"))
        assertTrue(out, out.contains("This phone's key is $key"))
        assertEquals(checked, controllerKeyFromRejection(raw))
        assertEquals(checked, grantGrantee(raw, key))
        assertEquals(key, grantGrantee("signed grant required", key))
        assertEquals("", controllerKeyFromRejection("signed grant required; run grant issue --node $node"))
    }

    @Test
    fun decorationWithoutKeyStillNamesTheMissingController() {
        val out = decorateGrantFailure("signed grant required", node, null)
        assertTrue(out, out.contains("still reading this phone's key"))
        assertTrue(out, out.contains("--grantee <this phone's controller public key>"))
        assertTrue(isGrantFixNote(out))
        assertFalse(isGrantFixNote("signed grant required"))
    }

    @Test
    fun importWritesGrantWhereRememberGrantsLooks() {
        val dir = tmp.newFolder("files")
        val target = importGrantJson(dir, node, key, grantJson()).getOrThrow()
        assertEquals(File(dir, "grants/$node.json").absolutePath, target.absolutePath)
        assertTrue(target.readText().contains("\"node_id\":\"$node\""))
    }

    @Test
    fun importLowercasesTheGrantFile() {
        val dir = tmp.newFolder("files")
        val upper = node.uppercase()
        val target = importGrantJson(dir, upper, key, grantJson(nodeId = upper)).getOrThrow()
        assertEquals(File(dir, "grants/$node.json"), target)
    }

    @Test
    fun importRejectsAnotherNodesGrant() {
        val dir = tmp.newFolder("files")
        val other = "12".repeat(32)
        val error = importGrantJson(dir, node, key, grantJson(nodeId = other)).exceptionOrNull()
        assertTrue(error?.message.orEmpty(), error?.message.orEmpty().contains("for node $other"))
    }

    @Test
    fun importRejectsAnotherDevicesGrant() {
        val dir = tmp.newFolder("files")
        val other = "34".repeat(32)
        val error = importGrantJson(dir, node, key, grantJson(grantee = other)).exceptionOrNull()
        assertTrue(error?.message.orEmpty(), error?.message.orEmpty().contains("not this controller"))
    }

    @Test
    fun importRejectsUnsafeNodeIds() {
        val dir = tmp.newFolder("files")
        val unsafe = "../../escape"
        val error = importGrantJson(dir, unsafe, key, grantJson(nodeId = unsafe)).exceptionOrNull()
        assertTrue(error?.message.orEmpty(), error?.message.orEmpty().contains("64-character public id"))
        assertFalse(File(dir.parentFile, "escape.json").exists())
    }

    @Test
    fun importRejectsCliSummaryAndUnsignedJson() {
        val dir = tmp.newFolder("files")
        val summary = JSONObject().put("status", "ok").toString()
        assertTrue(
            importGrantJson(dir, node, key, summary).exceptionOrNull()
                ?.message.orEmpty().contains("no node_id"),
        )
        assertTrue(
            importGrantJson(dir, node, key, grantJson(signature = "")).exceptionOrNull()
                ?.message.orEmpty().contains("no sig_hex"),
        )
        assertTrue(
            importGrantJson(dir, node, key, "not json").exceptionOrNull()
                ?.message.orEmpty().contains("not valid JSON"),
        )
    }
}
