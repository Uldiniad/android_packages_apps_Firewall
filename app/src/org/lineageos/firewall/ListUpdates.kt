/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.os.ParcelFileDescriptor
import android.os.RemoteException
import android.os.UserManager
import android.os.storage.StorageManager
import android.util.Log
import java.io.Closeable
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

private const val TAG = "Firewall"
private const val JOB_DAILY = 1
private const val JOB_NEW = 2

/**
 * Downloads lists for the service, which keeps them: each day on unmetered networks, and lists
 * added since on any network. A full user's copy of the app checks the lists of its profiles too.
 */
object ListUpdates {
    /** Checks every list once a day while the phone is on an unmetered network. */
    fun scheduleDaily(context: Context) {
        val jobs = context.getSystemService(JobScheduler::class.java)
        if (context.getSystemService(UserManager::class.java).isProfile) return
        if (jobs.getPendingJob(JOB_DAILY) != null) return
        jobs.schedule(
            JobInfo.Builder(JOB_DAILY, ComponentName(context, ListUpdateJob::class.java))
                .setPeriodic(TimeUnit.DAYS.toMillis(1))
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_UNMETERED)
                .setPersisted(true)
                .build()
        )
    }

    /** Downloads the lists that have never been downloaded, on any network, as the user waits. */
    fun checkNew(context: Context) {
        context
            .getSystemService(JobScheduler::class.java)
            .schedule(
                JobInfo.Builder(JOB_NEW, ComponentName(context, ListUpdateJob::class.java))
                    .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                    .build()
            )
    }

    /** A list read into the form the service takes, in a file of the app's that goes on close. */
    class Content(val file: File) : Closeable {
        override fun close() {
            file.delete()
        }
    }

    /**
     * Reads a list as the service takes it; null if it holds nothing the firewall can use. With
     * checkCount, a list whose header counts other than what it holds is refused, as cut short.
     * Throws [ListException] when the list is refused, with the reason as an IFirewall error.
     */
    fun read(
        context: Context,
        input: InputStream,
        subdomains: Boolean,
        checkCount: Boolean = false,
    ): Content? {
        val builder = ListContent.Builder()
        val result =
            ListParser.parse(
                input.bufferedReader(Charsets.UTF_8),
                subdomains,
                entriesThatFit(),
                Long.MAX_VALUE,
                builder,
            )
        if (result.tooBig()) throw ListException(IFirewall.LIST_ERROR_MEMORY)
        if (checkCount && result.declared() != ListParser.NO_COUNT &&
            result.declared() != result.lines()
        ) {
            throw ListException(IFirewall.LIST_ERROR_COUNT)
        }
        if (result.taken() == 0) return null
        val content = builder.build()
        val file = File.createTempFile("list", null, context.cacheDir)
        try {
            FileOutputStream(file).use { out ->
                context
                    .getSystemService(StorageManager::class.java)
                    .allocateBytes(out.fd, content.size())
                val buffered = out.buffered()
                content.write(buffered)
                buffered.flush()
            }
        } catch (e: IOException) {
            file.delete()
            throw ListException(IFirewall.LIST_ERROR_STORAGE)
        }
        return Content(file)
    }

    /**
     * How many entries the builder has room for: it keeps 8 bytes each and needs about three
     * times that while its array grows and when it sorts.
     */
    private fun entriesThatFit(): Int {
        val runtime = Runtime.getRuntime()
        val free = runtime.maxMemory() - (runtime.totalMemory() - runtime.freeMemory())
        return (free / 24).coerceIn(0, Int.MAX_VALUE.toLong()).toInt()
    }

    class ListException(val error: Int) : Exception()

    /** Checks the lists of the user and its profiles; true if a network failure wants a retry. */
    internal fun checkAll(
        context: Context,
        onlyNew: Boolean,
        running: (HttpURLConnection?) -> Unit,
    ): Boolean {
        val lists =
            context.getSystemService(UserManager::class.java).userProfiles.flatMap { user ->
                try {
                    Firewall.service.getLists(user.identifier).toList()
                } catch (e: RemoteException) {
                    emptyList()
                }
            }
        var retry = false
        for (list in lists.filter { it.url != null }.distinctBy { it.id }) {
            if (onlyNew && list.changedMillis != 0L) continue
            try {
                retry = retry or !check(context, list, running)
            } catch (e: RemoteException) {
                return true
            } catch (e: RuntimeException) {
                // One list's trouble doesn't keep the others from their checks.
                Log.e(TAG, "List check failed", e)
            }
        }
        return retry or !checkSafeSearch(onlyNew, running)
    }

    /**
     * Checks Google's search domains for Safe Search, while a user has it on, as a list is
     * checked; false on network failure.
     */
    private fun checkSafeSearch(onlyNew: Boolean, running: (HttpURLConnection?) -> Unit): Boolean {
        val kept =
            try {
                Firewall.service.safeSearchDomains
            } catch (e: RemoteException) {
                return true
            } ?: return true
        if (onlyNew && kept.checkedMillis != 0L) return true
        val connection =
            try {
                URL(GoogleDomains.URL).openConnection() as HttpURLConnection
            } catch (e: IOException) {
                return false
            }
        running(connection)
        try {
            kept.etag?.let { connection.setRequestProperty("If-None-Match", it) }
            kept.lastModified?.let { connection.setRequestProperty("If-Modified-Since", it) }
            val checked = SafeSearchDomains()
            when (connection.responseCode) {
                HttpURLConnection.HTTP_NOT_MODIFIED -> {}
                HttpURLConnection.HTTP_OK -> {
                    // A download that isn't Google's list leaves the domains as they were.
                    val names =
                        connection.inputStream.bufferedReader(Charsets.UTF_8).use {
                            GoogleDomains.parse(it)
                        } ?: return true
                    checked.names = names.toTypedArray()
                    checked.etag = connection.getHeaderField("ETag")
                    checked.lastModified = connection.getHeaderField("Last-Modified")
                }
                else -> return true
            }
            Firewall.service.setSafeSearchDomains(checked)
            return true
        } catch (e: IOException) {
            Log.w(TAG, "Safe Search's check failed", e)
            return false
        } catch (e: RemoteException) {
            return true
        } finally {
            running(null)
            connection.disconnect()
        }
    }

    /** Checks one list for changes and hands the service what it holds; false on network failure. */
    private fun check(
        context: Context,
        list: FirewallList,
        running: (HttpURLConnection?) -> Unit,
    ): Boolean {
        val connection =
            try {
                URL(list.url).openConnection() as HttpURLConnection
            } catch (e: IOException) {
                Firewall.service.setListChecked(list.id, IFirewall.LIST_ERROR_NETWORK, 0)
                return false
            }
        running(connection)
        try {
            list.etag?.let { connection.setRequestProperty("If-None-Match", it) }
            list.lastModified?.let { connection.setRequestProperty("If-Modified-Since", it) }
            val status = connection.responseCode
            when (status) {
                HttpURLConnection.HTTP_NOT_MODIFIED -> Firewall.service.setListChecked(list.id, 0, 0)
                HttpURLConnection.HTTP_OK -> {
                    val content =
                        try {
                            connection.inputStream.use {
                                read(context, it, list.subdomains, checkCount = true)
                            }
                        } catch (e: ListException) {
                            Firewall.service.setListChecked(list.id, e.error, 0)
                            return true
                        }
                    if (content == null) {
                        Firewall.service.setListChecked(list.id, IFirewall.LIST_ERROR_NOT_A_LIST, 0)
                        return true
                    }
                    content.use {
                        ParcelFileDescriptor.open(it.file, ParcelFileDescriptor.MODE_READ_ONLY)
                            .use { fd ->
                                Firewall.service.setListContent(
                                    list.id,
                                    fd,
                                    null,
                                    null,
                                    connection.getHeaderField("ETag"),
                                    connection.getHeaderField("Last-Modified"),
                                )
                            }
                    }
                }
                // Redirects that leave https aren't followed, and come here.
                else -> Firewall.service.setListChecked(list.id, IFirewall.LIST_ERROR_SERVER, status)
            }
            return true
        } catch (e: IOException) {
            Log.w(TAG, "List check failed", e)
            try {
                Firewall.service.setListChecked(list.id, IFirewall.LIST_ERROR_NETWORK, 0)
            } catch (remote: RemoteException) {
                // The service is gone; the next check reports it.
            }
            return false
        } catch (e: RemoteException) {
            return true
        } finally {
            running(null)
            connection.disconnect()
        }
    }
}

/** Runs the checks of [ListUpdates] as JobScheduler asks. */
class ListUpdateJob : JobService() {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    @Volatile private var connection: HttpURLConnection? = null

    override fun onStartJob(params: JobParameters): Boolean {
        scope.launch {
            val retry = ListUpdates.checkAll(this@ListUpdateJob, params.jobId != JOB_DAILY) {
                connection = it
            }
            jobFinished(params, retry)
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        scope.cancel()
        // Ends a download the system cut short, which picks up at the next run.
        connection?.disconnect()
        return true
    }
}
