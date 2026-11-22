package app.agentlink.node

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.content.Intent
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

    override fun onUnbind(intent: Intent?): Boolean {
        if (instance === this) instance = null
        return super.onUnbind(intent)
    }

    override fun onDestroy() {
        if (instance === this) instance = null
        super.onDestroy()
    }

    override fun onAccessibilityEvent(event: android.view.accessibility.AccessibilityEvent?) {}

    override fun onInterrupt() {}

    fun tap(x: Float, y: Float): Boolean = swipe(x, y, x, y, 40)

    fun swipe(x1: Float, y1: Float, x2: Float, y2: Float, durationMs: Long): Boolean {
        if (isGuardedSystemUiActive()) return false
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
        if (isGuardedSystemUiActive()) return false
        val keys = rawKeysForText(text)
        if (keys != null && sendRaw(keys)) return true
        return replaceText(text)
    }

    fun key(name: String): Boolean {
        if (isGuardedSystemUiActive()) return false
        val keys = rawKeysForName(name)
        if (keys != null && sendRaw(keys)) return true
        return when (name.lowercase()) {
            "enter", "return" -> enter()
            "backspace" -> backspaceFallback()
            else -> if (name.length == 1) typeText(name) else false
        }
    }

    fun enter(): Boolean {
        if (isGuardedSystemUiActive()) return false
        if (sendRaw(listOf(RawKey(KeyEvent.KEYCODE_ENTER)))) return true
        val node = focusedEditable() ?: return false
        return try {
            if (Build.VERSION.SDK_INT >= 30) {
                val enter = AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER
                node.performAction(enter.id)
            } else {
                false
            }
        } finally {
            recycleSafely(node)
        }
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
        return try {
            val args = Bundle().apply {
                putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text)
            }
            node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
        } finally {
            recycleSafely(node)
        }
    }

    private fun backspaceFallback(): Boolean {
        val node = focusedEditable() ?: return false
        return try {
            val current = node.text?.toString().orEmpty()
            if (current.isEmpty()) return false
            val args = Bundle().apply {
                putCharSequence(
                    AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,
                    current.dropLast(1),
                )
            }
            node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
        } finally {
            recycleSafely(node)
        }
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
        if (isGuardedSystemUiActive()) return false
        val root = rootInActiveWindow ?: windows.firstOrNull()?.root ?: return false
        val hit = find(root, text, id)
        if (hit == null) {
            recycleSafely(root)
            return false
        }
        try {
            if (hit.performAction(AccessibilityNodeInfo.ACTION_CLICK)) return true
            var parent = hit.parent
            while (parent != null) {
                val next = parent.parent
                val clicked = try {
                    parent.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                } finally {
                    if (parent !== root && parent !== hit) recycleSafely(parent)
                }
                if (clicked) {
                    if (next != null && next !== root && next !== hit) recycleSafely(next)
                    return true
                }
                parent = next
            }
            return false
        } finally {
            if (hit !== root) recycleSafely(hit)
            recycleSafely(root)
        }
    }

    fun tree(): JSONObject {
        val nodes = JSONArray()
        var count = 0
        fun walk(node: AccessibilityNodeInfo?, depth: Int) {
            if (node == null || depth > 14 || count >= 200) return
            count++
            val bounds = Rect()
            node.getBoundsInScreen(bounds)
            val password = node.isPassword
            nodes.put(
                JSONObject()
                    .put("text", if (password) "" else (node.text?.toString() ?: ""))
                    .put("desc", if (password) "" else (node.contentDescription?.toString() ?: ""))
                    .put("id", node.viewIdResourceName ?: "")
                    .put("class", node.className?.toString() ?: "")
                    .put("clickable", node.isClickable)
                    .put("editable", node.isEditable)
                    .put("password", password)
                    .put("bounds", JSONArray(listOf(bounds.left, bounds.top, bounds.right, bounds.bottom))),
            )
            for (i in 0 until node.childCount) {
                val child = node.getChild(i)
                try {
                    walk(child, depth + 1)
                } finally {
                    recycleSafely(child)
                }
            }
        }
        val roots = windows.mapNotNull { it.root }.ifEmpty { listOfNotNull(rootInActiveWindow) }
        for (root in roots) {
            try {
                walk(root, 0)
            } finally {
                recycleSafely(root)
            }
        }
        return JSONObject().put("nodes", nodes).put("truncated", count >= 200)
    }

    private fun isGuardedSystemUiActive(): Boolean {
        if (allowSystemDialogControl) return false
        val root = rootInActiveWindow ?: return false
        return try {
            val pkg = root.packageName?.toString()?.trim()?.lowercase().orEmpty()
            isGuardedPackage(pkg)
        } finally {
            recycleSafely(root)
        }
    }

    private fun focusedEditable(): AccessibilityNodeInfo? {
        val root = rootInActiveWindow ?: return null
        val focused = root.findFocus(AccessibilityNodeInfo.FOCUS_INPUT)
        if (focused != null) {
            if (focused.isEditable) {
                if (focused !== root) recycleSafely(root)
                return focused
            }
            if (focused !== root) recycleSafely(focused)
        }
        val hit = firstEditable(root)
        if (hit !== root) recycleSafely(root)
        return hit
    }

    private fun firstEditable(node: AccessibilityNodeInfo?): AccessibilityNodeInfo? {
        if (node == null) return null
        if (node.isEditable) return node
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            val hit = firstEditable(child)
            if (hit != null) {
                if (hit !== child) recycleSafely(child)
                return hit
            }
            recycleSafely(child)
        }
        return null
    }

    private fun find(node: AccessibilityNodeInfo?, text: String?, id: String?): AccessibilityNodeInfo? {
        if (node == null) return null
        val password = node.isPassword
        val label = if (password) "" else node.text?.toString().orEmpty()
        val desc = if (password) "" else node.contentDescription?.toString().orEmpty()
        val viewId = node.viewIdResourceName.orEmpty()
        val textHit = !text.isNullOrBlank() && (label.contains(text, true) || desc.contains(text, true))
        val idHit = !id.isNullOrBlank() && viewId == id
        if (textHit || idHit) return node
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            val hit = find(child, text, id)
            if (hit != null) {
                if (hit !== child) recycleSafely(child)
                return hit
            }
            recycleSafely(child)
        }
        return null
    }

    private fun recycleSafely(node: AccessibilityNodeInfo?) {
        if (node == null) return
        @Suppress("DEPRECATION")
        runCatching { node.recycle() }
    }

    companion object {
        @Volatile
        var instance: AgentAccessibilityService? = null

        @Volatile
        var allowSystemDialogControl: Boolean = false

        private val GUARDED_PACKAGES = setOf(
            "com.android.permissioncontroller",
            "com.google.android.permissioncontroller",
            "com.android.packageinstaller",
            "com.google.android.packageinstaller",
            "com.android.settings",
            "moe.shizuku.privileged.api",
        )

        internal fun isGuardedPackage(packageName: String): Boolean {
            return packageName.trim().lowercase() in GUARDED_PACKAGES
        }
    }
}
