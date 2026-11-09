package app.agentlink.node

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.graphics.Path
import android.graphics.Rect
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.view.KeyEvent
import android.view.accessibility.AccessibilityNodeInfo
import app.agentlink.model.RawKey
import app.agentlink.model.rawKeysForName
import app.agentlink.model.rawKeysForText
import org.json.JSONArray
import org.json.JSONObject

class AgentAccessibilityService : AccessibilityService() {
    override fun onServiceConnected() {
        instance = this
    }

    override fun onDestroy() {
        if (instance === this) instance = null
        super.onDestroy()
    }

    override fun onAccessibilityEvent(event: android.view.accessibility.AccessibilityEvent?) {}

    override fun onInterrupt() {}

    fun tap(x: Float, y: Float): Boolean = swipe(x, y, x, y, 40)

    fun swipe(x1: Float, y1: Float, x2: Float, y2: Float, durationMs: Long): Boolean {
        val path = Path().apply {
            moveTo(x1, y1)
            if (x1 != x2 || y1 != y2) lineTo(x2, y2)
        }
        val stroke = GestureDescription.StrokeDescription(path, 0, durationMs.coerceIn(1, 5_000))
        val gesture = GestureDescription.Builder().addStroke(stroke).build()
        return dispatchGesture(gesture, null, null)
    }

    /**
     * Prefer raw key events on API 33+, where the accessibility service can
     * send them through its input connection without being the system IME.
     * That connection only exists for a focused editor. Anything else, and
     * every API below 33, replaces the field text or sends IME enter.
     * Key events never reach games or views that ignore the input connection,
     * and they are not global hardware keys.
     */
    fun typeText(text: String): Boolean {
        val keys = rawKeysForText(text)
        if (keys != null && sendRaw(keys)) return true
        return replaceText(text)
    }

    fun key(name: String): Boolean {
        val keys = rawKeysForName(name)
        if (keys != null && sendRaw(keys)) return true
        return when (name.lowercase()) {
            "enter", "return" -> enter()
            "backspace" -> backspaceFallback()
            else -> if (name.length == 1) typeText(name) else false
        }
    }

    fun enter(): Boolean {
        if (sendRaw(listOf(RawKey(KeyEvent.KEYCODE_ENTER)))) return true
        val node = focusedEditable() ?: return false
        if (Build.VERSION.SDK_INT >= 30) {
            val enter = AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER
            if (node.performAction(enter.id)) return true
        }
        return false
    }

    private fun sendRaw(keys: List<RawKey>): Boolean {
        if (Build.VERSION.SDK_INT < 33 || keys.isEmpty()) return false
        val connection = inputMethod?.currentInputConnection ?: return false
        val now = SystemClock.uptimeMillis()
        for (key in keys) {
            val down = KeyEvent(now, now, KeyEvent.ACTION_DOWN, key.code, 0, key.meta)
            val up = KeyEvent(now, now, KeyEvent.ACTION_UP, key.code, 0, key.meta)
            connection.sendKeyEvent(down)
            connection.sendKeyEvent(up)
        }
        return true
    }

    private fun replaceText(text: String): Boolean {
        val node = focusedEditable() ?: return false
        val args = Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text)
        }
        return node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
    }

    private fun backspaceFallback(): Boolean {
        val node = focusedEditable() ?: return false
        val current = node.text?.toString().orEmpty()
        if (current.isEmpty()) return false
        val args = Bundle().apply {
            putCharSequence(
                AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,
                current.dropLast(1),
            )
        }
        return node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
    }

    fun global(name: String): Boolean {
        val action = when (name) {
            "back" -> GLOBAL_ACTION_BACK
            "home" -> GLOBAL_ACTION_HOME
            "recents" -> GLOBAL_ACTION_RECENTS
            "notifications" -> GLOBAL_ACTION_NOTIFICATIONS
            "quick_settings" -> GLOBAL_ACTION_QUICK_SETTINGS
            "power" -> GLOBAL_ACTION_POWER_DIALOG
            else -> return false
        }
        return performGlobalAction(action)
    }

    fun clickElement(text: String?, id: String?): Boolean {
        val root = rootInActiveWindow ?: windows.firstOrNull()?.root ?: return false
        val hit = find(root, text, id) ?: return false
        if (hit.performAction(AccessibilityNodeInfo.ACTION_CLICK)) return true
        var parent = hit.parent
        while (parent != null) {
            if (parent.performAction(AccessibilityNodeInfo.ACTION_CLICK)) return true
            parent = parent.parent
        }
        return false
    }

    fun tree(): JSONObject {
        val nodes = JSONArray()
        var count = 0
        fun walk(node: AccessibilityNodeInfo?, depth: Int) {
            if (node == null || depth > 14 || count >= 200) return
            count++
            val bounds = Rect()
            node.getBoundsInScreen(bounds)
            nodes.put(
                JSONObject()
                    .put("text", node.text?.toString() ?: "")
                    .put("desc", node.contentDescription?.toString() ?: "")
                    .put("id", node.viewIdResourceName ?: "")
                    .put("class", node.className?.toString() ?: "")
                    .put("clickable", node.isClickable)
                    .put("editable", node.isEditable)
                    .put("bounds", JSONArray(listOf(bounds.left, bounds.top, bounds.right, bounds.bottom))),
            )
            for (i in 0 until node.childCount) {
                val child = node.getChild(i)
                walk(child, depth + 1)
                child?.recycle()
            }
        }
        val roots = windows.mapNotNull { it.root }.ifEmpty { listOfNotNull(rootInActiveWindow) }
        for (root in roots) {
            walk(root, 0)
            root.recycle()
        }
        return JSONObject().put("nodes", nodes).put("truncated", count >= 200)
    }

    private fun focusedEditable(): AccessibilityNodeInfo? {
        val focused = rootInActiveWindow?.findFocus(AccessibilityNodeInfo.FOCUS_INPUT)
        if (focused != null && focused.isEditable) return focused
        return firstEditable(rootInActiveWindow)
    }

    private fun firstEditable(node: AccessibilityNodeInfo?): AccessibilityNodeInfo? {
        if (node == null) return null
        if (node.isEditable) return node
        for (i in 0 until node.childCount) {
            val hit = firstEditable(node.getChild(i))
            if (hit != null) return hit
        }
        return null
    }

    private fun find(node: AccessibilityNodeInfo?, text: String?, id: String?): AccessibilityNodeInfo? {
        if (node == null) return null
        val label = node.text?.toString().orEmpty()
        val desc = node.contentDescription?.toString().orEmpty()
        val viewId = node.viewIdResourceName.orEmpty()
        val textHit = !text.isNullOrBlank() && (label.contains(text, true) || desc.contains(text, true))
        val idHit = !id.isNullOrBlank() && viewId == id
        if (textHit || idHit) return node
        for (i in 0 until node.childCount) {
            val hit = find(node.getChild(i), text, id)
            if (hit != null) return hit
        }
        return null
    }

    companion object {
        @Volatile
        var instance: AgentAccessibilityService? = null
    }
}
