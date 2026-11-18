package io.github.leemikepop.trustprobe.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.leemikepop.trustprobe.R
import io.github.leemikepop.trustprobe.core.EngineEvent
import io.github.leemikepop.trustprobe.session.SessionState
import kotlinx.coroutines.delay

/** Countdown, what to do now, the connections seen so far (newest first) and a Stop button. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SessionScreen(vm: TrustProbeViewModel) {
    val state by vm.sessionState.collectAsStateWithLifecycle()
    val events by vm.liveEvents.collectAsStateWithLifecycle()
    val running = state as? SessionState.Running

    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(running?.endsAt) {
        while (true) {
            now = System.currentTimeMillis()
            delay(1_000)
        }
    }
    val remainingSec = running?.let { ((it.endsAt - now) / 1_000).coerceAtLeast(0) } ?: 0

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(title = { Text(stringResource(R.string.session_title, running?.let { vm.labelFor(it.packageName) }.orEmpty())) })
        },
    ) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(stringResource(R.string.session_prompt), style = MaterialTheme.typography.bodyLarge)
            Text(
                stringResource(R.string.session_remaining, formatRemaining(remainingSec)),
                style = MaterialTheme.typography.headlineMedium,
            )
            Text(stringResource(R.string.session_events), style = MaterialTheme.typography.titleSmall)
            if (events.isEmpty()) Text(stringResource(R.string.session_waiting))
            LazyColumn(Modifier.weight(1f)) {
                itemsIndexed(events.asReversed(), key = { i, _ -> events.size - i }) { _, e ->
                    ListItem(headlineContent = { Text(e.host) }, supportingContent = { Text(eventText(e)) })
                }
            }
            Button(
                onClick = vm::stop,
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp),
            ) { Text(stringResource(R.string.session_stop)) }
        }
    }
}

@Composable
private fun eventText(e: EngineEvent): String = when (e) {
    is EngineEvent.Probed -> stringResource(R.string.event_probed, e.result.case.name, e.result.kind.name)
    is EngineEvent.Forwarded -> stringResource(R.string.event_forwarded, e.reason.name)
    is EngineEvent.QuicDropped -> stringResource(R.string.event_quic)
}

private fun formatRemaining(totalSec: Long): String = "%d:%02d".format(totalSec / 60, totalSec % 60)
