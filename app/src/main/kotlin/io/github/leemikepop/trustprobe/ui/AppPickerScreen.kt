package io.github.leemikepop.trustprobe.ui

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.leemikepop.trustprobe.R

/**
 * Pick an app and a time limit, then start. Start order: VPN consent, then (API 33+) the
 * notification permission (the test runs even if it is denied), then the ViewModel opens the
 * session and starts the tunnel service.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppPickerScreen(vm: TrustProbeViewModel) {
    val apps by vm.apps.collectAsStateWithLifecycle()
    val query by vm.query.collectAsStateWithLifecycle()
    val minutes by vm.durationMin.collectAsStateWithLifecycle()
    val selected by vm.selected.collectAsStateWithLifecycle()
    val starting by vm.starting.collectAsStateWithLifecycle()
    val context = LocalContext.current

    fun startSelected() = selected?.let(vm::start) ?: Unit

    val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        startSelected() // granted or not: the service runs either way, only its notification is hidden
    }
    fun afterConsent() {
        val needsAsk = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        if (needsAsk) notifications.launch(Manifest.permission.POST_NOTIFICATIONS) else startSelected()
    }
    val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) afterConsent()
    }
    fun onStart() {
        val prepare = VpnService.prepare(context)
        if (prepare != null) consent.launch(prepare) else afterConsent()
    }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text(stringResource(R.string.picker_title)) },
                actions = { TextButton(onClick = vm::openHistory) { Text(stringResource(R.string.history)) } },
            )
        },
        bottomBar = {
            Button(
                onClick = ::onStart,
                enabled = selected != null && !starting,
                modifier = Modifier.fillMaxWidth().padding(16.dp),
            ) {
                Text(stringResource(if (starting) R.string.picker_starting else R.string.picker_start))
            }
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            OutlinedTextField(
                value = query,
                onValueChange = vm::setQuery,
                label = { Text(stringResource(R.string.picker_search)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
            )
            Row(
                Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(stringResource(R.string.picker_duration), style = MaterialTheme.typography.labelLarge)
                for (m in TrustProbeViewModel.DURATIONS_MIN) {
                    FilterChip(
                        selected = m == minutes,
                        onClick = { vm.setDuration(m) },
                        label = { Text(stringResource(R.string.picker_minutes, m)) },
                    )
                }
            }
            if (apps.isEmpty()) {
                Text(
                    stringResource(R.string.picker_empty),
                    modifier = Modifier.padding(16.dp),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            LazyColumn(Modifier.weight(1f), contentPadding = PaddingValues(bottom = 8.dp)) {
                items(apps, key = { it.packageName }) { app ->
                    val isSelected = app.packageName == selected?.packageName
                    ListItem(
                        headlineContent = { Text(app.label) },
                        supportingContent = { Text(app.packageName) },
                        colors = ListItemDefaults.colors(
                            containerColor = if (isSelected) MaterialTheme.colorScheme.secondaryContainer
                            else MaterialTheme.colorScheme.surface,
                        ),
                        modifier = Modifier.clickable { vm.select(app) },
                    )
                }
            }
        }
    }
}
