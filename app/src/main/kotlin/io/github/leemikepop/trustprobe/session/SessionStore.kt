package io.github.leemikepop.trustprobe.session

import io.github.leemikepop.trustprobe.core.EngineEvent
import java.util.concurrent.atomic.AtomicLong

/** Persists sessions and their (already redacted) events. Room-backed from Task 12. */
interface SessionStore {
    fun open(packageName: String, appLabel: String, startedAt: Long, durationLimitSec: Int): Long
    fun append(sessionId: Long, e: EngineEvent)
    fun finish(sessionId: Long, endedAt: Long)

    /** Deletes the session and its events (a session that never really started). */
    fun discard(sessionId: Long)
}

/** Placeholder until the Room store exists: hands out ids and keeps nothing. */
class InMemorySessionStore : SessionStore {
    private val nextId = AtomicLong(1)

    override fun open(packageName: String, appLabel: String, startedAt: Long, durationLimitSec: Int): Long =
        nextId.getAndIncrement()

    override fun append(sessionId: Long, e: EngineEvent) = Unit

    override fun finish(sessionId: Long, endedAt: Long) = Unit

    override fun discard(sessionId: Long) = Unit
}
