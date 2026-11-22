/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.os.RemoteException
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.navigation.NavType
import androidx.navigation.navArgument
import com.android.settingslib.spa.framework.common.SettingsPageProvider
import com.android.settingslib.spa.framework.compose.navigator
import com.android.settingslib.spa.widget.dialog.AlertDialogButton
import com.android.settingslib.spa.widget.dialog.rememberAlertDialogPresenter
import com.android.settingslib.spa.widget.preference.Preference
import com.android.settingslib.spa.widget.preference.PreferenceModel
import com.android.settingslib.spa.widget.scaffold.RegularScaffold
import com.android.settingslib.spa.widget.ui.Footer
import com.android.settingslib.spa.widget.ui.SettingsBody
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** One user's rules saved to a file, or replaced by a file's, as backups carry them. */
object ExportImportPageProvider : SettingsPageProvider {
    private const val USER_ID = "rt_userId"
    override val name = "ExportImport"
    override val parameter = listOf(navArgument(USER_ID) { type = NavType.IntType })

    fun route(userId: Int) = "$name/$userId"

    @Composable fun navigator(userId: Int) = navigator(route = route(userId))

    @Composable
    override fun Page(arguments: Bundle?) {
        ExportImportPage(checkNotNull(arguments).getInt(USER_ID))
    }
}

private const val MIME_TYPE = "text/xml"

/** The most a file may hold, well within what one binder call carries. */
private const val MAX_PAYLOAD = 512 * 1024

@Composable
private fun ExportImportPage(userId: Int) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val failed =
        rememberAlertDialogPresenter(
            confirmButton = AlertDialogButton(stringResource(android.R.string.ok)),
            title = stringResource(R.string.import_failed_title),
            text = { SettingsBody(stringResource(R.string.import_failed_text)) },
        )
    val saveFile =
        rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument(MIME_TYPE)) { uri ->
            if (uri != null) scope.launch { context.exportRules(userId, uri) }
        }
    val openFile =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) scope.launch { if (!context.importRules(userId, uri)) failed.open() }
        }
    val replace =
        rememberAlertDialogPresenter(
            confirmButton =
                AlertDialogButton(stringResource(R.string.choose_file)) {
                    // Any type, as files sent through mail or chat apps often lose theirs.
                    openFile.launch(arrayOf("*/*"))
                },
            dismissButton = AlertDialogButton(stringResource(android.R.string.cancel)),
            title = stringResource(R.string.import_rules_title),
            text = { SettingsBody(stringResource(R.string.import_rules_text)) },
        )
    RegularScaffold(title = stringResource(R.string.export_import_title)) {
        Preference(
            object : PreferenceModel {
                override val title = stringResource(R.string.export_rules)
                override val summary = { context.getString(R.string.export_rules_summary) }
                override val onClick = {
                    saveFile.launch(context.getString(R.string.export_file_name))
                }
            }
        )
        Preference(
            object : PreferenceModel {
                override val title = stringResource(R.string.import_rules)
                override val summary = { context.getString(R.string.import_rules_summary) }
                override val onClick = replace::open
            }
        )
        Footer(stringResource(R.string.export_import_footer))
    }
}

/** Saves the user's rules to the file, and tells whether it worked. */
private suspend fun Context.exportRules(userId: Int, uri: Uri) {
    val saved =
        try {
            val payload = Firewall.call { getBackupPayload(userId) }
            withContext(Dispatchers.IO) {
                contentResolver.openOutputStream(uri, "wt")?.use { it.write(payload) } != null
            }
        } catch (e: IOException) {
            false
        } catch (e: RemoteException) {
            false
        }
    val result = if (saved) R.string.rules_exported else R.string.export_failed
    Toast.makeText(this, result, Toast.LENGTH_SHORT).show()
}

/** Replaces the user's rules with the file's; false if it isn't an export or can't be read. */
private suspend fun Context.importRules(userId: Int, uri: Uri): Boolean {
    try {
        val payload =
            withContext(Dispatchers.IO) {
                contentResolver.openInputStream(uri)?.use { it.readNBytes(MAX_PAYLOAD + 1) }
            }
        if (payload == null || payload.size > MAX_PAYLOAD) return false
        Firewall.call { applyRestore(userId, payload) }
    } catch (e: IOException) {
        return false
    } catch (e: IllegalArgumentException) {
        return false
    } catch (e: RemoteException) {
        return false
    }
    ListUpdates.checkNew(this)
    Toast.makeText(this, R.string.rules_imported, Toast.LENGTH_SHORT).show()
    return true
}

/** The app list's entry for saving the user's rules to a file, or replacing them with one's. */
@Composable
fun ExportImportEntry(userId: Int) {
    val context = LocalContext.current
    Preference(
        object : PreferenceModel {
            override val title = stringResource(R.string.export_import_title)
            override val summary = { context.getString(R.string.export_import_summary) }
            override val onClick = ExportImportPageProvider.navigator(userId)
        }
    )
}
