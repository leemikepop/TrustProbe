package io.github.leemikepop.trustprobe.data

import io.github.leemikepop.trustprobe.core.EngineEvent
import io.github.leemikepop.trustprobe.core.report.Report
import io.github.leemikepop.trustprobe.core.report.ReportBuilder
import io.github.leemikepop.trustprobe.session.SessionStore
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json

/**
 * Room-backed [SessionStore]. Room forbids main-thread I/O and [append] arrives concurrently from
 * engine threads, so every write runs on one private thread, in submission order.
 *
 * [open] blocks until its row exists, so `SessionController.begin()` must be called off the main
 * thread (for example from `Dispatchers.IO`). [append] and [finish] are fire-and-forget.
 *
 * Verdicts are never stored; [report] recomputes them from the events with [ReportBuilder].
 */
class RoomSessionStore(private val dao: SessionDao) : SessionStore {
    private val writer: ExecutorService = Executors.newSingleThreadExecutor { r ->
        Thread(r, "trustprobe-room-writer").apply { isDaemon = true }
    }

    override fun open(packageName: String, appLabel: String, startedAt: Long, durationLimitSec: Int): Long =
        writer.submit<Long> {
            dao.insert(SessionEntity(packageName = packageName, appLabel = appLabel, startedAt = startedAt, endedAt = null, durationLimitSec = durationLimitSec))
        }.get()

    override fun append(sessionId: Long, e: EngineEvent) {
        writer.execute {
            dao.insertEvent(
                EventEntity(
                    sessionId = sessionId,
                    host = e.host,
                    kind = e::class.simpleName!!,
                    atMillis = e.atMillis,
                    json = JSON.encodeToString(EngineEvent.serializer(), e),
                ),
            )
        }
    }

    override fun finish(sessionId: Long, endedAt: Long) {
        writer.execute { dao.finish(sessionId, endedAt) }
    }

    /** Rebuilds the report of a stored session, or null if there is no such session. */
    suspend fun report(sessionId: Long): Report? {
        val s = dao.session(sessionId) ?: return null
        val events = dao.events(sessionId).map { decode(it.json) }
        // A session that never finished (process died) is treated as having run to its time limit.
        val endedAt = s.endedAt ?: (s.startedAt + s.durationLimitSec * 1000L)
        return ReportBuilder.build(s.packageName, s.appLabel, s.startedAt, endedAt, events)
    }

    /** Drains queued writes and stops the writer thread. Safe to call more than once. */
    fun close() {
        writer.shutdown()
        writer.awaitTermination(10, TimeUnit.SECONDS)
    }

    companion object {
        private val JSON = Json { encodeDefaults = true }

        fun decode(json: String): EngineEvent = JSON.decodeFromString(EngineEvent.serializer(), json)
    }
}
