package com.vulnchat.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vulnchat.BuildConfig
import com.vulnchat.R
import com.vulnchat.data.UiMessage

// ─────────────────────────────────────────────────────────────────────
// Screen entry point
// ─────────────────────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    viewModel: ChatViewModel = viewModel()
) {
    val messages by viewModel.messages.collectAsStateWithLifecycle()
    val uiState  by viewModel.uiState.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()

    // Auto-scroll to the latest message whenever the list changes
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.lastIndex)
        }
    }

    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    title = {
                        Text(
                            text  = "VulnChat",
                            style = MaterialTheme.typography.titleMedium
                        )
                    },
                    actions = {
                        IconButton(onClick = { viewModel.clearConversation() }) {
                            Icon(
                                imageVector        = Icons.Default.Clear,
                                contentDescription = "Clear conversation"
                            )
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = MaterialTheme.colorScheme.surface
                    )
                )
                // Security mode banner — always visible so the demo context is clear
                SecurityModeBanner()
            }
        },
        bottomBar = {
            MessageInputBar(
                isStreaming = uiState.isStreaming,
                onSend      = viewModel::sendMessage,
                onCancel    = viewModel::cancelStreaming
            )
        }
    ) { innerPadding ->
        LazyColumn(
            state           = listState,
            modifier        = Modifier
                .fillMaxSize()
                .padding(innerPadding),
            contentPadding  = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(
                items = messages,
                key   = { it.id }
            ) { message ->
                MessageBubble(message = message)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Security mode banner
// ─────────────────────────────────────────────────────────────────────

/**
 * Persistent banner at the top of the screen indicating the active build mode.
 *
 * This exists purely for demo clarity — an interviewer watching the screen
 * can see at a glance which build is running without needing to ask.
 *
 * Vulnerable: amber background (warning colour)
 * Hardened:   green/teal background (safe colour)
 */
@Composable
private fun SecurityModeBanner() {
    val (text, containerColor, textColor) = if (BuildConfig.SECURE_MODE) {
        Triple(
            stringResource(R.string.banner_hardened),
            Color(0xFFE1F5EE),   // teal-50
            Color(0xFF0F6E56)    // teal-600
        )
    } else {
        Triple(
            stringResource(R.string.banner_vulnerable),
            Color(0xFFFAEEDA),   // amber-50
            Color(0xFF854F0B)    // amber-600
        )
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(containerColor)
            .padding(horizontal = 16.dp, vertical = 6.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text  = text,
            style = MaterialTheme.typography.labelMedium,
            color = textColor
        )
    }
}

// ─────────────────────────────────────────────────────────────────────
// Message bubble
// ─────────────────────────────────────────────────────────────────────

@Composable
private fun MessageBubble(message: UiMessage) {
    val isUser   = message.role == UiMessage.Role.USER
    val isSystem = message.role == UiMessage.Role.SYSTEM
    val isError  = message.state == UiMessage.State.ERROR

    if (isSystem) {
        SystemNotice(text = message.content)
        return
    }

    Row(
        modifier       = Modifier.fillMaxWidth(),
        horizontalArrangement = if (isUser) Arrangement.End else Arrangement.Start
    ) {
        Surface(
            shape   = RoundedCornerShape(
                topStart     = if (isUser) 16.dp else 4.dp,
                topEnd       = if (isUser) 4.dp else 16.dp,
                bottomStart  = 16.dp,
                bottomEnd    = 16.dp
            ),
            color   = when {
                isError -> MaterialTheme.colorScheme.errorContainer
                isUser  -> MaterialTheme.colorScheme.primaryContainer
                else    -> MaterialTheme.colorScheme.surfaceVariant
            },
            modifier = Modifier.widthIn(max = 300.dp)
        ) {
            Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                // Sender label
                Text(
                    text  = if (isUser) stringResource(R.string.label_you)
                            else stringResource(R.string.label_assistant),
                    style = MaterialTheme.typography.labelSmall,
                    color = if (isUser) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.secondary
                )

                Spacer(modifier = Modifier.height(2.dp))

                // Message content
                Text(
                    text  = message.content,
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (isError) MaterialTheme.colorScheme.onErrorContainer
                            else MaterialTheme.colorScheme.onSurface
                )

                // Streaming cursor
                if (message.state == UiMessage.State.STREAMING) {
                    StreamingCursor()
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// System notice — for blocked messages and rate-limit warnings
// ─────────────────────────────────────────────────────────────────────

@Composable
private fun SystemNotice(text: String) {
    Box(
        modifier          = Modifier.fillMaxWidth(),
        contentAlignment  = Alignment.Center
    ) {
        Surface(
            shape  = RoundedCornerShape(8.dp),
            color  = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.6f)
        ) {
            Text(
                text     = text,
                style    = MaterialTheme.typography.labelSmall,
                color    = MaterialTheme.colorScheme.onErrorContainer,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Animated streaming cursor
// ─────────────────────────────────────────────────────────────────────

@Composable
private fun StreamingCursor() {
    val transition = rememberInfiniteTransition(label = "cursor")
    val alpha by transition.animateFloat(
        initialValue = 1f,
        targetValue  = 0f,
        animationSpec = infiniteRepeatable(
            animation  = tween(durationMillis = 500),
            repeatMode = RepeatMode.Reverse
        ),
        label = "cursor_alpha"
    )
    Box(
        modifier = Modifier
            .padding(top = 2.dp)
            .size(width = 8.dp, height = 14.dp)
            .alpha(alpha)
            .background(
                color = MaterialTheme.colorScheme.secondary,
                shape = RoundedCornerShape(2.dp)
            )
    )
}

// ─────────────────────────────────────────────────────────────────────
// Message input bar
// ─────────────────────────────────────────────────────────────────────

@Composable
private fun MessageInputBar(
    isStreaming: Boolean,
    onSend:     (String) -> Unit,
    onCancel:   () -> Unit
) {
    var inputText by remember { mutableStateOf("") }

    Surface(
        tonalElevation = 2.dp,
        modifier = Modifier
            .fillMaxWidth()
            .navigationBarsPadding()
            .imePadding()
    ) {
        Row(
            modifier = Modifier
                .padding(horizontal = 8.dp, vertical = 8.dp),
            verticalAlignment = Alignment.Bottom
        ) {
            TextField(
                value         = inputText,
                onValueChange = { inputText = it },
                modifier      = Modifier.weight(1f),
                placeholder   = {
                    Text(
                        text  = stringResource(R.string.hint_message_input),
                        style = MaterialTheme.typography.bodyMedium
                    )
                },
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.Sentences,
                    imeAction      = ImeAction.Send
                ),
                keyboardActions = KeyboardActions(
                    onSend = {
                        if (inputText.isNotBlank() && !isStreaming) {
                            onSend(inputText)
                            inputText = ""
                        }
                    }
                ),
                maxLines = 5,
                colors   = TextFieldDefaults.colors(
                    focusedContainerColor   = Color.Transparent,
                    unfocusedContainerColor = Color.Transparent,
                    focusedIndicatorColor   = Color.Transparent,
                    unfocusedIndicatorColor = Color.Transparent
                )
            )

            // Send / Cancel button
            AnimatedVisibility(
                visible = isStreaming,
                enter   = fadeIn(),
                exit    = fadeOut()
            ) {
                IconButton(onClick = onCancel) {
                    Icon(
                        imageVector        = Icons.Default.Stop,
                        contentDescription = "Stop",
                        tint               = MaterialTheme.colorScheme.error
                    )
                }
            }

            AnimatedVisibility(
                visible = !isStreaming,
                enter   = fadeIn(),
                exit    = fadeOut()
            ) {
                IconButton(
                    onClick  = {
                        if (inputText.isNotBlank()) {
                            onSend(inputText)
                            inputText = ""
                        }
                    },
                    enabled  = inputText.isNotBlank()
                ) {
                    Icon(
                        imageVector        = Icons.AutoMirrored.Filled.Send,
                        contentDescription = stringResource(R.string.button_send),
                        tint               = if (inputText.isNotBlank())
                                                 MaterialTheme.colorScheme.primary
                                             else
                                                 MaterialTheme.colorScheme.outline
                    )
                }
            }
        }
    }
}
