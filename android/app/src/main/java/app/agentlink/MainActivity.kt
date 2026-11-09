package app.agentlink

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat
import app.agentlink.account.AccountApi
import app.agentlink.account.EnrollLink
import app.agentlink.account.NativeAccount
import app.agentlink.account.parseEnroll
import app.agentlink.bridge.LinkBridge
import app.agentlink.bridge.NativeBridge
import app.agentlink.ui.AgentApp
import app.agentlink.ui.AgentTheme

class MainActivity : ComponentActivity() {
    private var enroll by mutableStateOf<EnrollLink?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.auto(Color.TRANSPARENT, Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.auto(Color.TRANSPARENT, Color.TRANSPARENT),
        )
        enroll = parseEnroll(intent?.data)
        val bridge = AppGraph.bridge ?: NativeBridge()
        val account = AppGraph.account ?: NativeAccount(this)
        setContent {
            val dark = isSystemInDarkTheme()
            AgentTheme(darkTheme = dark) {
                val view = LocalView.current
                SideEffect {
                    val controller = WindowCompat.getInsetsController(window, view)
                    controller.isAppearanceLightStatusBars = !dark
                    controller.isAppearanceLightNavigationBars = !dark
                }
                Scaffold(
                    containerColor = MaterialTheme.colorScheme.background,
                    contentColor = MaterialTheme.colorScheme.onBackground,
                    contentWindowInsets = WindowInsets.safeDrawing,
                ) { padding ->
                    Box(Modifier.padding(padding).fillMaxSize()) {
                        AgentApp(bridge, account, enroll)
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        enroll = parseEnroll(intent.data)
    }
}

object AppGraph {
    var bridge: LinkBridge? = null
    var account: AccountApi? = null
}
