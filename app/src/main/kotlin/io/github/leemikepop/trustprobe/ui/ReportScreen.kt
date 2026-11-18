package io.github.leemikepop.trustprobe.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.leemikepop.trustprobe.R
import io.github.leemikepop.trustprobe.core.EngineEvent
import io.github.leemikepop.trustprobe.core.evidence.RequestEvidence
import io.github.leemikepop.trustprobe.core.probe.HostVerdict
import io.github.leemikepop.trustprobe.core.probe.OutcomeKind
import io.github.leemikepop.trustprobe.core.probe.ProbeCase
import io.github.leemikepop.trustprobe.core.probe.Verdict
import io.github.leemikepop.trustprobe.core.report.Report
import io.github.leemikepop.trustprobe.core.report.ReportRenderer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Verdict banner, per-host results, masked evidence, export, and (this session only) full content. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ReportScreen(vm: TrustProbeViewModel) {
    val ui by vm.reportUi.collectAsStateWithLifecycle()
    val shown = ui ?: return
    val report = shown.report
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val saved = stringResource(R.string.report_exported)
    val failed = stringResource(R.string.report_export_failed)

    // The text is rendered when the file is written, from the masked report only.
    fun exporter(render: (Report) -> String): (Uri?) -> Unit = { uri ->
        if (uri != null) {
            scope.launch {
                val ok = withContext(Dispatchers.IO) {
                    runCatching {
                        context.contentResolver.openOutputStream(uri, "wt")!!.use { it.write(render(report).toByteArray()) }
                    }.isSuccess
                }
                snackbar.showSnackbar(if (ok) saved else failed)
            }
        }
    }
    val exportMd = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/markdown"), exporter(ReportRenderer::markdown),
    )
    val exportJson = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"), exporter(ReportRenderer::json),
    )

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text(report.appLabel) },
                navigationIcon = { TextButton(onClick = vm::back) { Text(stringResource(R.string.back)) } },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        LazyColumn(
            Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item { Banner(report) }
            item {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { exportMd.launch(exportFileName(report, "md")) }) {
                        Text(stringResource(R.string.report_export_md))
                    }
                    OutlinedButton(onClick = { exportJson.launch(exportFileName(report, "json")) }) {
                        Text(stringResource(R.string.report_export_json))
                    }
                }
            }
            if (shown.canReveal) {
                item {
                    OutlinedButton(onClick = vm::toggleReveal) {
                        Text(stringResource(if (shown.revealed) R.string.report_hide_full else R.string.report_show_full))
                    }
                }
            }
            item { Text(stringResource(R.string.report_hosts), style = MaterialTheme.typography.titleMedium) }
            items(report.hosts, key = { it.host }) { host ->
                HostCard(host, report, vm, shown.revealed)
            }
        }
    }
}

@Composable
private fun Banner(report: Report) {
    val vulnerable = report.hosts.count { it.verdict == Verdict.VULNERABLE }
    val inconclusive = report.hosts.count { it.verdict == Verdict.INCONCLUSIVE }
    val (container, label) = when (report.appVerdict) {
        Verdict.VULNERABLE -> MaterialTheme.colorScheme.errorContainer to R.string.verdict_vulnerable
        Verdict.PASS -> MaterialTheme.colorScheme.primaryContainer to R.string.verdict_pass
        Verdict.INCONCLUSIVE -> MaterialTheme.colorScheme.tertiaryContainer to R.string.verdict_inconclusive
    }
    Card(colors = CardDefaults.cardColors(containerColor = container), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(stringResource(label), style = MaterialTheme.typography.headlineMedium)
            report.appReason?.let { Text(it.name, style = MaterialTheme.typography.titleSmall) }
            Text(stringResource(R.string.report_summary, vulnerable, report.hosts.size, inconclusive))
            Text(report.packageName, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun HostCard(host: HostVerdict, report: Report, vm: TrustProbeViewModel, revealed: Boolean) {
    val accepted = if (host.verdict == Verdict.VULNERABLE) acceptedRequest(report, host.host) else null
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(host.host, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                Text(
                    host.verdict.name,
                    color = if (host.verdict == Verdict.VULNERABLE) MaterialTheme.colorScheme.error else Color.Unspecified,
                    style = MaterialTheme.typography.labelLarge,
                )
            }
            (host.severity?.name ?: host.reason?.name)?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
            Text(
                stringResource(R.string.report_cases, host.casesRun.joinToString(", ") { it.name }.ifEmpty { "-" }),
                style = MaterialTheme.typography.bodySmall,
            )
            if (host.selfSignedUntested) Text(stringResource(R.string.report_self_signed_untested), style = MaterialTheme.typography.bodySmall)
            if (host.hostnameUntested) Text(stringResource(R.string.report_hostname_untested), style = MaterialTheme.typography.bodySmall)
            if (host.closedAfterHandshake) Text(stringResource(R.string.report_closed_after_handshake), style = MaterialTheme.typography.bodySmall)
            if (accepted != null) {
                val (case, evidence) = accepted
                Text(stringResource(R.string.report_evidence), style = MaterialTheme.typography.labelLarge)
                SelectionContainer {
                    Text(maskedEvidenceText(evidence), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                }
                if (revealed) {
                    Text(stringResource(R.string.report_full_warning), style = MaterialTheme.typography.labelSmall)
                    val full = vm.fullContent(host.host, case)
                    SelectionContainer {
                        Text(
                            full ?: stringResource(R.string.report_full_missing),
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }
    }
}

/** The first accepted probe of [host] that carries evidence, with the case that was accepted. */
private fun acceptedRequest(report: Report, host: String): Pair<ProbeCase, RequestEvidence>? =
    report.events.filterIsInstance<EngineEvent.Probed>()
        .firstOrNull { it.host == host && it.result.kind == OutcomeKind.ACCEPTED && it.result.evidence != null }
        ?.let { it.result.case to it.result.evidence!! }

private fun maskedEvidenceText(e: RequestEvidence): String = buildString {
    appendLine("${e.method ?: "-"} ${e.path ?: "-"} (${e.protocol})")
    appendLine("Host: ${e.host ?: "-"}")
    for (h in e.headers) appendLine("${h.name}: ${h.preview} (length ${h.length})")
}.trimEnd()
