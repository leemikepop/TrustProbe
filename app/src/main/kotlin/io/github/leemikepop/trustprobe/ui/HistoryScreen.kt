package io.github.leemikepop.trustprobe.ui

import android.text.format.DateFormat
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ListItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.leemikepop.trustprobe.R
import io.github.leemikepop.trustprobe.data.SessionEntity
import java.util.Date

/**
 * Past tests, newest first. The verdict is not computed for the list; it is rebuilt from the
 * stored events when a row is opened.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HistoryScreen(vm: TrustProbeViewModel) {
    val sessions by vm.sessions.collectAsStateWithLifecycle()
    val rows: List<SessionEntity>? = sessions

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text(stringResource(R.string.history_title)) },
                navigationIcon = { TextButton(onClick = vm::back) { Text(stringResource(R.string.back)) } },
            )
        },
    ) { padding ->
        if (rows != null && rows.isEmpty()) {
            Text(stringResource(R.string.history_empty), modifier = Modifier.padding(padding).padding(16.dp))
        }
        LazyColumn(Modifier.fillMaxSize().padding(padding)) {
            items(rows.orEmpty(), key = { it.id }) { s ->
                ListItem(
                    headlineContent = { Text(s.appLabel) },
                    supportingContent = { Text("${s.packageName}\n${DateFormat.format("yyyy-MM-dd HH:mm", Date(s.startedAt))}") },
                    trailingContent = {
                        TextButton(onClick = { vm.openHistory(s.id) }) { Text(stringResource(R.string.history_open)) }
                    },
                )
            }
        }
    }
}
