package io.github.leemikepop.trustprobe.core.probe

object VerdictEngine {
    private val REASON_ORDER = listOf(
        InconclusiveReason.NO_SNI,
        InconclusiveReason.TIMEOUT,
        InconclusiveReason.ERROR,
        InconclusiveReason.NO_CONNECTIONS,
    )

    /** [results] are all results for [host] in arrival order, including late parallel ones. */
    fun host(host: String, results: List<ProbeResult>, sawNoSni: Boolean = false): HostVerdict {
        val decisive = results.filter { it.kind == OutcomeKind.ACCEPTED || it.kind == OutcomeKind.REJECTED }
        val casesRun = decisive.map { it.case }.distinct()
        fun accepted(c: ProbeCase) = decisive.any { it.case == c && it.kind == OutcomeKind.ACCEPTED }

        val t1 = accepted(ProbeCase.T1_SELF_SIGNED)
        val t2 = accepted(ProbeCase.T2_UNTRUSTED_CA)
        val t3 = accepted(ProbeCase.T3_WRONG_HOST)

        if (t1 || t2 || t3) {
            val severity = when {
                t3 -> Severity.ACCEPTS_ANY_CERT
                t2 -> Severity.NO_CHAIN_VALIDATION
                else -> Severity.ACCEPTS_SELF_SIGNED
            }
            return HostVerdict(
                host, Verdict.VULNERABLE, severity, null, casesRun,
                selfSignedUntested = false,
                hostnameUntested = severity == Severity.NO_CHAIN_VALIDATION &&
                    ProbeCase.T3_WRONG_HOST !in casesRun,
            )
        }
        val decidingT2 = decisive.firstOrNull { it.case == ProbeCase.T2_UNTRUSTED_CA }
        if (decidingT2 != null) {
            return HostVerdict(
                host, Verdict.PASS, null, null, casesRun,
                selfSignedUntested = ProbeCase.T1_SELF_SIGNED !in casesRun,
                hostnameUntested = false,
                closedAfterHandshake = decidingT2.rejectStage == RejectStage.CLOSED_AFTER_HANDSHAKE,
            )
        }
        val reason = when {
            sawNoSni -> InconclusiveReason.NO_SNI
            results.any { it.kind == OutcomeKind.TIMEOUT } -> InconclusiveReason.TIMEOUT
            results.any { it.kind == OutcomeKind.ERROR } -> InconclusiveReason.ERROR
            else -> InconclusiveReason.NO_CONNECTIONS
        }
        return HostVerdict(host, Verdict.INCONCLUSIVE, null, reason, casesRun, false, false)
    }

    fun app(hosts: List<HostVerdict>): Pair<Verdict, InconclusiveReason?> = when {
        hosts.any { it.verdict == Verdict.VULNERABLE } -> Verdict.VULNERABLE to null
        hosts.any { it.verdict == Verdict.PASS } -> Verdict.PASS to null
        else -> {
            val reasons = hosts.mapNotNull { it.reason }
            Verdict.INCONCLUSIVE to (REASON_ORDER.firstOrNull { it in reasons } ?: InconclusiveReason.NO_CONNECTIONS)
        }
    }
}
