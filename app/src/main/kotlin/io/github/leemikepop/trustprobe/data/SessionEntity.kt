package io.github.leemikepop.trustprobe.data

import androidx.room.Entity
import androidx.room.PrimaryKey

/** One test run. [endedAt] stays null until the session finishes (or forever if the process died). */
@Entity
data class SessionEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val packageName: String,
    val appLabel: String,
    val startedAt: Long,
    val endedAt: Long?,
    val durationLimitSec: Int,
)
