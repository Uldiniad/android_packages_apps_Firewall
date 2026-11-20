/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.os.ServiceManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.conflate
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext

/** The firewall service, which keeps every rule; this app shows and changes them through it. */
object Firewall {
    val service: IFirewall by lazy {
        IFirewall.Stub.asInterface(checkNotNull(ServiceManager.getService("firewall")))
    }

    /** Emits now and after every change, wherever the change came from. */
    private val changes =
        callbackFlow {
                val listener =
                    object : IFirewallListener.Stub() {
                        override fun onChanged() {
                            trySend(Unit)
                        }
                    }
                service.registerListener(listener)
                send(Unit)
                awaitClose { service.unregisterListener(listener) }
            }
            .conflate()

    internal fun <T> load(read: IFirewall.() -> T): Flow<T> =
        changes.map { service.read() }.flowOn(Dispatchers.IO)

    fun appRules(userId: Int) = load { getAppRulesForUser(userId).associateBy { it.packageName } }



    fun running() = load { isRunning() }


    suspend fun <T> call(change: IFirewall.() -> T): T =
        withContext(Dispatchers.IO) { service.change() }
}
