package io.github.leemikepop.trustprobe.ui

import android.os.Build
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.leemikepop.trustprobe.R

/** Material 3, following the system dark/light setting (dynamic colours where the OS has them). */
@Composable
fun TrustProbeTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val context = LocalContext.current
    val colors = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        dark -> darkColorScheme()
        else -> lightColorScheme()
    }
    MaterialTheme(colorScheme = colors, content = content)
}

/** Switches between the four screens; the screen itself lives in [TrustProbeViewModel.screen]. */
@Composable
fun TrustProbeRoot(vm: TrustProbeViewModel) {
    val screen by vm.screen.collectAsStateWithLifecycle()
    val error by vm.error.collectAsStateWithLifecycle()

    // Back from the picker leaves the app; back from the live session leaves the test running.
    BackHandler(enabled = screen == Screen.Report || screen == Screen.History) { vm.back() }

    when (screen) {
        Screen.Picker -> AppPickerScreen(vm)
        Screen.Session -> SessionScreen(vm)
        Screen.Report -> ReportScreen(vm)
        Screen.History -> HistoryScreen(vm)
    }

    error?.let { message ->
        AlertDialog(
            onDismissRequest = vm::dismissError,
            text = { Text(message) },
            confirmButton = { TextButton(onClick = vm::dismissError) { Text(stringResource(R.string.dismiss)) } },
        )
    }
}
