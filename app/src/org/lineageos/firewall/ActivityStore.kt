/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.os.RemoteException
import android.os.storage.StorageManager
import android.util.Log
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * The user's activity log, in this app's own credential-encrypted storage, which Android doesn't
 * back up: Storage settings count it, and Clear storage clears it. Once Android warns that storage
 * is low, each new entry takes the oldest one's place instead of growing the log.
 */
class ActivityStore private constructor(private val context: Context) :
    SQLiteOpenHelper(context, NAME, null, 1) {

    /** An entry as the activity page shows it. */
    data class Entry(
        val key: String,
        val uid: Int,
        val kind: Int,
        val protocol: Int,
        val address: String?,
        val port: Int,
        val name: String?,
        val allowed: Boolean,
        val reasons: Int,
        val network: Int,
        val firstMillis: Long,
        val lastMillis: Long,
        val count: Long,
    )

    private val _changes = MutableStateFlow(0L)
    /** Changes whenever entries are saved or cleared. */
    val changes = _changes.asStateFlow()

    /** Whether the latest save took the place of old entries, as storage was low. */
    @Volatile
    var trimming = false
        private set

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            "CREATE TABLE entries (key TEXT PRIMARY KEY, uid INTEGER, kind INTEGER, " +
                "protocol INTEGER, address TEXT, port INTEGER, name TEXT, allowed INTEGER, " +
                "reasons INTEGER, network INTEGER, first INTEGER, last INTEGER, count INTEGER)"
        )
        db.execSQL("CREATE INDEX entries_last ON entries (last)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {}

    /** Saves the service's new entries; an entry that came before is brought up to date. */
    fun save(entries: List<ActivityEntry>) {
        if (entries.isEmpty()) return
        val db = writableDatabase
        db.beginTransaction()
        try {
            trimming = storageLow()
            if (trimming) {
                db.execSQL(
                    "DELETE FROM entries WHERE key IN " +
                        "(SELECT key FROM entries ORDER BY last LIMIT ?)",
                    arrayOf(entries.size),
                )
            }
            for (entry in entries) {
                db.execSQL(
                    "INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) " +
                        "ON CONFLICT (key) DO UPDATE SET last = max(last, excluded.last), " +
                        "count = max(count, excluded.count), " +
                        "reasons = reasons | excluded.reasons, " +
                        "name = coalesce(name, excluded.name), " +
                        "network = CASE excluded.network WHEN 0 THEN network " +
                        "ELSE excluded.network END",
                    arrayOf<Any?>(
                        entry.key,
                        entry.uid,
                        entry.kind,
                        entry.protocol,
                        entry.address,
                        entry.port,
                        entry.name,
                        if (entry.allowed) 1 else 0,
                        entry.reasons,
                        entry.network,
                        entry.firstMillis,
                        entry.lastMillis,
                        entry.count,
                    ),
                )
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
        _changes.value++
    }

    /** The newest entries first, up to [limit]: all, or only those allowed or refused. */
    fun entries(allowed: Boolean?, limit: Int): List<Entry> {
        val where = allowed?.let { "WHERE allowed = ${if (it) 1 else 0}" } ?: ""
        return readableDatabase
            .rawQuery("SELECT * FROM entries $where ORDER BY last DESC LIMIT $limit", null)
            .use { cursor ->
                buildList {
                    while (cursor.moveToNext()) {
                        add(
                            Entry(
                                key = cursor.getString(0),
                                uid = cursor.getInt(1),
                                kind = cursor.getInt(2),
                                protocol = cursor.getInt(3),
                                address = cursor.getString(4),
                                port = cursor.getInt(5),
                                name = cursor.getString(6),
                                allowed = cursor.getInt(7) != 0,
                                reasons = cursor.getInt(8),
                                network = cursor.getInt(9),
                                firstMillis = cursor.getLong(10),
                                lastMillis = cursor.getLong(11),
                                count = cursor.getLong(12),
                            )
                        )
                    }
                }
            }
    }

    /** The bytes the log takes, with its journal. */
    fun size(): Long {
        val db = context.getDatabasePath(NAME)
        return listOf(db, File("${db.path}-wal"), File("${db.path}-shm"), File("${db.path}-journal"))
            .sumOf { it.length() }
    }

    fun clear() {
        writableDatabase.delete("entries", null, null)
        writableDatabase.execSQL("VACUUM")
        trimming = false
        _changes.value++
    }

    /** Whether free space is under the line where Android warns that storage is low. */
    private fun storageLow(): Boolean {
        val data = context.dataDir
        return data.usableSpace < context.getSystemService(StorageManager::class.java)
            .getStorageLowBytes(data)
    }

    companion object {
        private const val NAME = "activity.db"
        @Volatile private var instance: ActivityStore? = null

        fun get(context: Context): ActivityStore =
            instance
                ?: synchronized(this) {
                    instance ?: ActivityStore(context.applicationContext).also { instance = it }
                }

        /** Takes the user's new entries from the service into the log. */
        fun takeNew(context: Context) {
            val entries =
                try {
                    Firewall.service.takeActivity(context.userId)
                } catch (e: RemoteException) {
                    Log.w("Firewall", "Couldn't take activity", e)
                    return
                }
            get(context).save(entries.toList())
        }
    }
}

/** The service's word that there are new entries, which go into the log at once. */
class ActivityReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val result = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                ActivityStore.takeNew(context)
            } finally {
                result.finish()
            }
        }
    }
}
