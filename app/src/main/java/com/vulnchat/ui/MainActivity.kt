package com.vulnchat.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.vulnchat.ui.theme.VulnChatTheme

/**
 * Single activity — Compose handles all navigation.
 *
 * The full chat screen (ChatScreen.kt) and ViewModel (ChatViewModel.kt)
 * will be wired in here once scaffolded.
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            VulnChatTheme {
                ChatScreen()
            }
        }
    }
}
