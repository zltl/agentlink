package app.agentlink.model

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class LiveControlTest {
    @Test
    fun annexBBecomesLengthPrefixedAvcWithACodecConfig() {
        val sps = byteArrayOf(0x67, 0x42, 0x00, 0x1f)
        val pps = byteArrayOf(0x68, 0xce.toByte(), 0x01)
        val idr = byteArrayOf(0x65, 0x88.toByte(), 0x84.toByte())
        val annex = ByteArray(4 + sps.size + 4 + pps.size + 4 + idr.size)
        var offset = 0
        for (nal in listOf(sps, pps, idr)) {
            annex[offset + 3] = 1
            nal.copyInto(annex, offset + 4)
            offset += 4 + nal.size
        }
        val unit = avcAccessUnit(annex)!!
        assertTrue(unit.keyframe)
        val config = unit.config!!
        assertEquals(1.toByte(), config[0])
        assertEquals(0x42.toByte(), config[1])
        assertEquals(0xFF.toByte(), config[4])
        assertEquals(3, unit.sample[3].toInt() and 0xff)
        assertEquals(3, unit.sample.size - 4)
        assertEquals(0x65.toByte(), unit.sample[4])
    }

    @Test
    fun deltaWithoutSpsHasNoCodecConfig() {
        val annex = byteArrayOf(0, 0, 0, 1, 0x41, 0x01)
        val unit = avcAccessUnit(annex)!!
        assertFalse(unit.keyframe)
        assertNull(unit.config)
        assertEquals(2, unit.sample.size - 4)
    }

    @Test
    fun hardwareDecoderWinsOverAndroidSoftware() {
        assertEquals(
            "OMX.qcom.video.decoder.avc",
            preferAvcDecoder(listOf("OMX.google.h264.decoder", "c2.android.avc.decoder", "OMX.qcom.video.decoder.avc")),
        )
        assertTrue(isSoftwareAvcDecoder("OMX.google.h264.decoder"))
        assertTrue(isSoftwareAvcDecoder("c2.android.avc.decoder"))
        assertFalse(isSoftwareAvcDecoder("OMX.qcom.video.decoder.avc"))
        assertEquals("OMX.google.h264.decoder", preferAvcDecoder(listOf("OMX.google.h264.decoder")))
    }

    @Test
    fun pointerBecomesPixelMouseAndGlobalsStayOnInject() {
        val tap = liveControlMessages("tap", 960, 480, x = 0.5f, y = 0.25f)
        assertEquals(2, tap.size)
        assertEquals("down", JSONObject(tap[0]).getString("action"))
        assertEquals(480, JSONObject(tap[0]).getInt("x"))
        assertEquals(120, JSONObject(tap[0]).getInt("y"))
        assertEquals("up", JSONObject(tap[1]).getString("action"))
        val swipe = liveControlMessages("swipe", 100, 100, x = 0f, y = 0f, x2 = 1f, y2 = 1f)
        assertEquals(listOf("down", "move", "up"), swipe.map { JSONObject(it).getString("action") })
        assertEquals(99, JSONObject(swipe[2]).getInt("x"))
        val typed = liveControlMessages("type", 1, 1, text = "hi")
        assertEquals("hi", JSONObject(typed.single()).getString("text"))
        val key = liveControlMessages("key", 1, 1, name = "enter")
        assertEquals("enter", JSONObject(key.single()).getString("keys"))
        assertTrue(liveControlMessages("global", 1, 1, name = "back").isEmpty())
    }

    @Test
    fun refusedOffersDoNotRetryAndATimeoutDoes() {
        assertFalse(liveFailureShouldRetry("live video is not available; fallback screenshot"))
        assertFalse(liveFailureShouldRetry("remote_view is not allowed on this node"))
        assertFalse(liveFailureShouldRetry("remote desktop streaming is denied on this node"))
        assertTrue(liveFailureShouldRetry("connection failed"))
        assertEquals(
            "Live video is not available. Showing screenshots.",
            liveFailureNote("live video is not available; fallback screenshot", screenshots = true),
        )
        assertTrue(liveStatus("h264", "minih264", false, 960, 480, "hw decode", 0.0).contains("sw encode"))
        assertTrue(liveStatus("h264", "minih264", false, 960, 480, "hw decode", 0.05).contains("5.0%"))
    }
}
