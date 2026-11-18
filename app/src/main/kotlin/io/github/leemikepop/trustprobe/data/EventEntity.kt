package io.github.leemikepop.trustprobe.data

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/** One redacted engine event; [json] is the serialized event, [kind] its simple class name. */
@Entity(indices = [Index("sessionId")])
data class EventEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val sessionId: Long,
    val host: String,
    val kind: String,
    val atMillis: Long,
    val json: String,
)
