package io.github.leemikepop.trustprobe.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface SessionDao {
    @Insert
    fun insert(s: SessionEntity): Long

    @Query("UPDATE SessionEntity SET endedAt = :endedAt WHERE id = :id")
    fun finish(id: Long, endedAt: Long)

    @Insert
    fun insertEvent(e: EventEntity)

    @Query("SELECT * FROM SessionEntity ORDER BY startedAt DESC")
    fun sessions(): Flow<List<SessionEntity>>

    @Query("SELECT * FROM SessionEntity WHERE id = :id")
    suspend fun session(id: Long): SessionEntity?

    @Query("SELECT * FROM EventEntity WHERE sessionId = :sessionId ORDER BY atMillis")
    suspend fun events(sessionId: Long): List<EventEntity>
}
