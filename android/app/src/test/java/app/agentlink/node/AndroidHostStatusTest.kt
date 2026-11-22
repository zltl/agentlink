package app.agentlink.node

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class AndroidHostStatusTest {
    @Test
    fun onStatusInvokesCallbackWithoutInfiniteRecursion() {
        val context: Context = ApplicationProvider.getApplicationContext()
        val delivered = mutableListOf<String>()
        val host = AndroidHost(
            context = context,
            saf = SafStore(context),
            shells = ShellSessions(),
            capture = ScreenGrabber(),
            allowShizuku = false,
            allowRoot = false,
            statusCallback = { delivered += it },
        )
        host.onStatus("""{"state":"online","detail":"connected"}""")
        assertEquals(listOf("""{"state":"online","detail":"connected"}"""), delivered)
    }
}
