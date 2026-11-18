package io.github.leemikepop.trustprobe.core

import io.github.leemikepop.trustprobe.core.probe.ProbeResult
import kotlinx.serialization.Serializable

enum class ForwardReason { HOST_DONE, NO_SNI, NOT_TLS, NON_TLS_PORT }

/** Something the [ProbeEngine] did with a connection or datagram of the app under test. */
@Serializable
sealed interface EngineEvent {
    val host: String
    val atMillis: Long

    /** A connection was answered with a bad certificate; [result] is what the app did. */
    @Serializable
    data class Probed(override val host: String, override val atMillis: Long, val result: ProbeResult) : EngineEvent

    /** A connection was passed through untouched. */
    @Serializable
    data class Forwarded(override val host: String, override val atMillis: Long, val reason: ForwardReason) : EngineEvent

    /** A UDP datagram to a QUIC port was dropped so the app falls back to TCP. */
    @Serializable
    data class QuicDropped(override val host: String, override val atMillis: Long) : EngineEvent
}
