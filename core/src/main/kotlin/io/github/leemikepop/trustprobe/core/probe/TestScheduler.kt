package io.github.leemikepop.trustprobe.core.probe

/**
 * Decides which bad-certificate case each new TLS connection to a host gets.
 * Per host: T2 first; T2 REJECTED -> T1, T2 ACCEPTED -> T3; after that the host is done (forward).
 * Parallel connections share the in-flight case. Thread-safe.
 */
class TestScheduler {
    private class HostState {
        var current = ProbeCase.T2_UNTRUSTED_CA
        var attempts = 0
        var done = false
    }

    private val lock = Any()
    private val hosts = HashMap<String, HostState>()

    /** The case to run for a new connection to [host], or null to forward it. */
    fun assign(host: String): ProbeCase? = synchronized(lock) {
        val state = hosts.getOrPut(host.lowercase()) { HostState() }
        if (state.done) null else state.current
    }

    fun report(host: String, result: ProbeResult) {
        synchronized(lock) {
            val state = hosts[host.lowercase()] ?: return
            if (state.done || result.case != state.current) return
            when (result.kind) {
                OutcomeKind.ACCEPTED, OutcomeKind.REJECTED -> advance(state, result.kind)
                OutcomeKind.TIMEOUT, OutcomeKind.ERROR -> {
                    state.attempts++
                    if (state.attempts >= MAX_ATTEMPTS_PER_CASE) state.done = true
                }
            }
        }
    }

    private fun advance(state: HostState, kind: OutcomeKind) {
        state.attempts = 0
        if (state.current == ProbeCase.T2_UNTRUSTED_CA) {
            state.current =
                if (kind == OutcomeKind.REJECTED) ProbeCase.T1_SELF_SIGNED else ProbeCase.T3_WRONG_HOST
        } else {
            state.done = true
        }
    }

    companion object {
        const val MAX_ATTEMPTS_PER_CASE = 2
    }
}
