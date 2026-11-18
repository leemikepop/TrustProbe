package io.github.leemikepop.trustprobe.testbed

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

private const val TAG = "TrustProbeTestbed"

private suspend fun runAndLog(s: Scenario): ScenarioRun {
    val r = runScenario(s)
    Log.i(TAG, "${s.name} attempts=${r.attempts} success=${r.success} elapsedMs=${r.elapsedMs}")
    return r
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val autorun = intent.getBooleanExtra("autorun", false)
        setContent {
            MaterialTheme {
                val results = remember { mutableStateMapOf<Scenario, ScenarioRun>() }
                val scope = rememberCoroutineScope()
                suspend fun runAll() {
                    for (s in Scenario.entries) results[s] = runAndLog(s)
                }
                LaunchedEffect(Unit) {
                    if (autorun) {
                        runAll()
                        Log.i(TAG, "AUTORUN_DONE")
                    }
                }
                Column(
                    Modifier.fillMaxSize().padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text("TrustProbe Testbed")
                    Button(onClick = { scope.launch { runAll() } }) { Text("Run all") }
                    for (s in Scenario.entries) {
                        Button(onClick = { scope.launch { results[s] = runAndLog(s) } }) {
                            Text("${s.name} (${s.host})")
                        }
                        val r = results[s]
                        Text(
                            if (r == null) "not run"
                            else "attempts=${r.attempts} success=${r.success} elapsedMs=${r.elapsedMs}",
                        )
                    }
                }
            }
        }
    }
}
