package app.agentlink.model

import android.view.KeyEvent

/**
 * A hardware-style key the accessibility service can try to inject.
 * [meta] uses [KeyEvent] meta flags such as [KeyEvent.META_SHIFT_ON].
 */
data class RawKey(val code: Int, val meta: Int = 0)

/**
 * Named keys and plain ASCII as Android key codes.
 *
 * Characters outside this set return null. The accessibility service then
 * falls back to replacing the focused field, which does not need an IME.
 */
fun rawKeysForName(name: String): List<RawKey>? = when (name.lowercase()) {
    "enter", "return" -> listOf(RawKey(KeyEvent.KEYCODE_ENTER))
    "tab" -> listOf(RawKey(KeyEvent.KEYCODE_TAB))
    "escape", "esc" -> listOf(RawKey(KeyEvent.KEYCODE_ESCAPE))
    "backspace" -> listOf(RawKey(KeyEvent.KEYCODE_DEL))
    "delete" -> listOf(RawKey(KeyEvent.KEYCODE_FORWARD_DEL))
    "space" -> listOf(RawKey(KeyEvent.KEYCODE_SPACE))
    "up" -> listOf(RawKey(KeyEvent.KEYCODE_DPAD_UP))
    "down" -> listOf(RawKey(KeyEvent.KEYCODE_DPAD_DOWN))
    "left" -> listOf(RawKey(KeyEvent.KEYCODE_DPAD_LEFT))
    "right" -> listOf(RawKey(KeyEvent.KEYCODE_DPAD_RIGHT))
    "home" -> listOf(RawKey(KeyEvent.KEYCODE_MOVE_HOME))
    "end" -> listOf(RawKey(KeyEvent.KEYCODE_MOVE_END))
    "pageup" -> listOf(RawKey(KeyEvent.KEYCODE_PAGE_UP))
    "pagedown" -> listOf(RawKey(KeyEvent.KEYCODE_PAGE_DOWN))
    else -> if (name.length == 1) rawKeyForChar(name[0])?.let { listOf(it) } else null
}

fun rawKeysForText(text: String): List<RawKey>? {
    if (text.isEmpty()) return emptyList()
    val keys = ArrayList<RawKey>(text.length)
    for (ch in text) {
        keys += rawKeyForChar(ch) ?: return null
    }
    return keys
}

private fun rawKeyForChar(ch: Char): RawKey? {
    if (ch in 'a'..'z') return RawKey(KeyEvent.KEYCODE_A + (ch - 'a'))
    if (ch in 'A'..'Z') return RawKey(KeyEvent.KEYCODE_A + (ch - 'A'), KeyEvent.META_SHIFT_ON)
    if (ch in '0'..'9') return RawKey(KeyEvent.KEYCODE_0 + (ch - '0'))
    return when (ch) {
        ' ' -> RawKey(KeyEvent.KEYCODE_SPACE)
        '\n', '\r' -> RawKey(KeyEvent.KEYCODE_ENTER)
        '\t' -> RawKey(KeyEvent.KEYCODE_TAB)
        '-' -> RawKey(KeyEvent.KEYCODE_MINUS)
        '=' -> RawKey(KeyEvent.KEYCODE_EQUALS)
        '[' -> RawKey(KeyEvent.KEYCODE_LEFT_BRACKET)
        ']' -> RawKey(KeyEvent.KEYCODE_RIGHT_BRACKET)
        '\\' -> RawKey(KeyEvent.KEYCODE_BACKSLASH)
        ';' -> RawKey(KeyEvent.KEYCODE_SEMICOLON)
        '\'' -> RawKey(KeyEvent.KEYCODE_APOSTROPHE)
        ',' -> RawKey(KeyEvent.KEYCODE_COMMA)
        '.' -> RawKey(KeyEvent.KEYCODE_PERIOD)
        '/' -> RawKey(KeyEvent.KEYCODE_SLASH)
        '`' -> RawKey(KeyEvent.KEYCODE_GRAVE)
        '!' -> RawKey(KeyEvent.KEYCODE_1, KeyEvent.META_SHIFT_ON)
        '@' -> RawKey(KeyEvent.KEYCODE_2, KeyEvent.META_SHIFT_ON)
        '#' -> RawKey(KeyEvent.KEYCODE_3, KeyEvent.META_SHIFT_ON)
        '$' -> RawKey(KeyEvent.KEYCODE_4, KeyEvent.META_SHIFT_ON)
        '%' -> RawKey(KeyEvent.KEYCODE_5, KeyEvent.META_SHIFT_ON)
        '^' -> RawKey(KeyEvent.KEYCODE_6, KeyEvent.META_SHIFT_ON)
        '&' -> RawKey(KeyEvent.KEYCODE_7, KeyEvent.META_SHIFT_ON)
        '*' -> RawKey(KeyEvent.KEYCODE_8, KeyEvent.META_SHIFT_ON)
        '(' -> RawKey(KeyEvent.KEYCODE_9, KeyEvent.META_SHIFT_ON)
        ')' -> RawKey(KeyEvent.KEYCODE_0, KeyEvent.META_SHIFT_ON)
        '_' -> RawKey(KeyEvent.KEYCODE_MINUS, KeyEvent.META_SHIFT_ON)
        '+' -> RawKey(KeyEvent.KEYCODE_EQUALS, KeyEvent.META_SHIFT_ON)
        '{' -> RawKey(KeyEvent.KEYCODE_LEFT_BRACKET, KeyEvent.META_SHIFT_ON)
        '}' -> RawKey(KeyEvent.KEYCODE_RIGHT_BRACKET, KeyEvent.META_SHIFT_ON)
        '|' -> RawKey(KeyEvent.KEYCODE_BACKSLASH, KeyEvent.META_SHIFT_ON)
        ':' -> RawKey(KeyEvent.KEYCODE_SEMICOLON, KeyEvent.META_SHIFT_ON)
        '"' -> RawKey(KeyEvent.KEYCODE_APOSTROPHE, KeyEvent.META_SHIFT_ON)
        '<' -> RawKey(KeyEvent.KEYCODE_COMMA, KeyEvent.META_SHIFT_ON)
        '>' -> RawKey(KeyEvent.KEYCODE_PERIOD, KeyEvent.META_SHIFT_ON)
        '?' -> RawKey(KeyEvent.KEYCODE_SLASH, KeyEvent.META_SHIFT_ON)
        '~' -> RawKey(KeyEvent.KEYCODE_GRAVE, KeyEvent.META_SHIFT_ON)
        else -> null
    }
}
