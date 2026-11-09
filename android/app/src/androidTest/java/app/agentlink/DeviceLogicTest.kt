package app.agentlink

import androidx.test.ext.junit.runners.AndroidJUnit4
import app.agentlink.model.gestureFromDrag
import app.agentlink.model.letterbox
import app.agentlink.model.mapTouch
import app.agentlink.model.planCommand
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DeviceLogicTest {
    @Test
    fun touchAndShellMatchTheUnitRules() {
        val box = letterbox(300f, 300f, 100f, 200f)
        val point = mapTouch(box, box.imageLeft + box.imageWidth, box.imageTop)
        assertEquals(1f, point!!.first, 0.02f)
        assertEquals(0f, point.second, 0.02f)
        assertEquals("swipe", gestureFromDrag(0f to 0f, 0.4f to 0.4f))
        assertEquals("shizuku", planCommand("id", emptyList(), shell = false, shizuku = true, root = false).via)
    }
}
