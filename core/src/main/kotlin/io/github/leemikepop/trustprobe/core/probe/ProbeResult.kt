package io.github.leemikepop.trustprobe.core.probe

import io.github.leemikepop.trustprobe.core.evidence.RequestEvidence
import kotlinx.serialization.Serializable

enum class OutcomeKind { ACCEPTED, REJECTED, TIMEOUT, ERROR }

enum class RejectStage { ALERT_OR_CLOSE_DURING_HANDSHAKE, CLOSED_AFTER_HANDSHAKE }

/**
 * What one probed connection showed. [rejectStage] is set only for [OutcomeKind.REJECTED];
 * [detail] is the underlying exception message, for reference only (never used for judging).
 */
@Serializable
data class ProbeResult(
    val case: ProbeCase,
    val kind: OutcomeKind,
    val rejectStage: RejectStage?,
    val detail: String?,
    val tlsVersion: String?,
    val evidence: RequestEvidence?,
    val durationMs: Long,
)
