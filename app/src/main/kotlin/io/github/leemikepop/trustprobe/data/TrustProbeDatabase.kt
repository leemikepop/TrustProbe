package io.github.leemikepop.trustprobe.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(entities = [SessionEntity::class, EventEntity::class], version = 1, exportSchema = true)
abstract class TrustProbeDatabase : RoomDatabase() {
    abstract fun sessionDao(): SessionDao

    companion object {
        fun create(context: Context): TrustProbeDatabase =
            Room.databaseBuilder(context, TrustProbeDatabase::class.java, "trustprobe.db").build()
    }
}
