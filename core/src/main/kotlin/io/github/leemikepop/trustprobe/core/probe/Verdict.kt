package io.github.leemikepop.trustprobe.core.probe

import kotlinx.serialization.Serializable

enum class Verdict { VULNERABLE, PASS, INCONCLUSIVE }

enum class Severity { ACCEPTS_ANY_CERT, NO_CHAIN_VALIDATION, ACCEPTS_SELF_SIGNED }

enum class InconclusiveReason { NO_CONNECTIONS, NO_SNI, TIMEOUT, ERROR }

@Serializable
data class HostVerdict(
    val host: String,
    val verdict: Verdict,
    val severity: Severity?,
    val reason: InconclusiveReason?,
    val casesRun: List<ProbeCase>,
    val selfSignedUntested: Boolean,
    val hostnameUntested: Boolean,
)
