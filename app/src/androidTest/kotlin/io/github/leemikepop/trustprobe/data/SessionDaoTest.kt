package io.github.leemikepop.trustprobe.data

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.leemikepop.trustprobe.core.EngineEvent
import io.github.leemikepop.trustprobe.core.ForwardReason
import io.github.leemikepop.trustprobe.core.probe.OutcomeKind
import io.github.leemikepop.trustprobe.core.probe.ProbeCase
import io.github.leemikepop.trustprobe.core.probe.ProbeResult
import io.github.leemikepop.trustprobe.core.probe.Verdict
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SessionDaoTest {
    private lateinit var db: TrustProbeDatabase
    private lateinit var store: RoomSessionStore

    private val probed = EngineEvent.Probed(
        host = "api.example.com",
        atMillis = 1_000,
        result = ProbeResult(
            case = ProbeCase.T1_SELF_SIGNED,
            kind = OutcomeKind.ACCEPTED,
            rejectStage = null,
            detail = null,
            tlsVersion = "TLSv1.3",
            evidence = null,
            durationMs = 42,
        ),
    )
    private val forwarded = EngineEvent.Forwarded("cdn.example.com", 2_000, ForwardReason.NO_SNI)
    private val quic = EngineEvent.QuicDropped("cdn.example.com", 3_000)

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(context, TrustProbeDatabase::class.java).build()
        store = RoomSessionStore(db.sessionDao())
    }

    @After
    fun tearDown() {
        store.close()
        db.close()
    }

    @Test
    fun insertAndReadEventsRoundTrip() = runBlocking {
        val id = store.open("com.example", "Example", 500, 60)
        listOf(probed, forwarded, quic).forEach { store.append(id, it) }
        store.close() // drains the queue
        val stored = db.sessionDao().events(id)
        assertEquals(listOf("Probed", "Forwarded", "QuicDropped"), stored.map { it.kind })
        assertEquals(listOf("api.example.com", "cdn.example.com", "cdn.example.com"), stored.map { it.host })
        assertEquals(listOf(probed, forwarded, quic), stored.map { RoomSessionStore.decode(it.json) })
    }

    @Test
    fun finishSetsEndedAt() = runBlocking {
        val id = store.open("com.example", "Example", 500, 60)
        assertNull(db.sessionDao().sessions().first().single().endedAt)
        store.finish(id, 9_000)
        store.close()
        assertEquals(9_000L, db.sessionDao().sessions().first().single().endedAt)
    }

    @Test
    fun sessionsOrderedNewestFirst() = runBlocking {
        val old = store.open("a", "A", 100, 60)
        val new = store.open("b", "B", 300, 60)
        val mid = store.open("c", "C", 200, 60)
        assertEquals(listOf(new, mid, old), db.sessionDao().sessions().first().map { it.id })
    }

    @Test
    fun reportIsRebuiltFromStoredEvents() = runBlocking {
        val id = store.open("com.example", "Example", 500, 60)
        store.append(id, probed)
        store.finish(id, 7_000)
        store.close()
        val report = store.report(id)
        assertNotNull(report)
        assertEquals("com.example", report!!.packageName)
        assertEquals(500L, report.startedAt)
        assertEquals(7_000L, report.endedAt)
        assertEquals(Verdict.VULNERABLE, report.appVerdict)
        assertEquals(listOf(probed), report.events)
        assertNull(store.report(id + 100))
    }

    @Test
    fun unfinishedSessionEndsAtDurationLimit() = runBlocking {
        val id = store.open("com.example", "Example", 500, 60)
        store.close()
        assertEquals(500L + 60_000, store.report(id)!!.endedAt)
    }
}
