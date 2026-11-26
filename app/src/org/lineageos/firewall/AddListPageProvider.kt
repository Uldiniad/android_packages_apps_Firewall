/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.os.RemoteException
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavType
import androidx.navigation.navArgument
import com.android.settingslib.spa.framework.common.SettingsPageProvider
import com.android.settingslib.spa.framework.compose.LocalNavController
import com.android.settingslib.spa.framework.compose.navigator
import com.android.settingslib.spa.widget.editor.SettingsOutlinedTextField
import com.android.settingslib.spa.widget.preference.Preference
import com.android.settingslib.spa.widget.preference.PreferenceModel
import com.android.settingslib.spa.widget.preference.SwitchPreference
import com.android.settingslib.spa.widget.preference.SwitchPreferenceModel
import com.android.settingslib.spa.widget.scaffold.RegularScaffold
import com.android.settingslib.spa.widget.ui.Category
import com.android.settingslib.spa.widget.ui.Footer
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val USER_ID = "rt_userId"
private const val PACKAGE_NAME = "rt_packageName"

/** Adds a list for all of a user's apps. */
object AddListPageProvider : SettingsPageProvider {
    override val name = "AddList"

    override val parameter = listOf(navArgument(USER_ID) { type = NavType.IntType })

    /** Adds a list for the app, or with a null packageName for all of the user's apps. */
    @Composable
    fun navigator(userId: Int, packageName: String?) =
        if (packageName == null) navigator(route = "$name/$userId")
        else AddAppListPageProvider.navigator(userId, packageName)

    @Composable
    override fun Page(arguments: Bundle?) {
        AddListPage(checkNotNull(arguments).getInt(USER_ID), null)
    }
}

/** Adds a list for one app. */
object AddAppListPageProvider : SettingsPageProvider {
    override val name = "AddAppList"

    override val parameter =
        listOf(
            navArgument(USER_ID) { type = NavType.IntType },
            navArgument(PACKAGE_NAME) { type = NavType.StringType },
        )

    @Composable
    fun navigator(userId: Int, packageName: String) =
        navigator(route = "$name/$userId/$packageName")

    @Composable
    override fun Page(arguments: Bundle?) {
        val args = checkNotNull(arguments)
        AddListPage(args.getInt(USER_ID), checkNotNull(args.getString(PACKAGE_NAME)))
    }
}

/** The suggested lists that suit the scope, then the user's own by address or from a file. */
@Composable
private fun AddListPage(userId: Int, packageName: String?) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val navController = LocalNavController.current
    val lists by remember(userId) { Firewall.lists(userId) }.collectAsStateWithLifecycle(null)
    var address by rememberSaveable { mutableStateOf("") }
    var invalid by rememberSaveable { mutableStateOf(false) }
    var subdomains by rememberSaveable { mutableStateOf(true) }
    val added = lists.orEmpty().filter { it.packageName == packageName }.mapNotNull { it.url }
    val add: (String, Boolean) -> Unit = { url, coversSubdomains ->
        scope.launch {
            if (context.addList(userId, packageName, url, coversSubdomains)) {
                navController.navigateBack()
            }
        }
    }
    val openFile =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) {
                scope.launch {
                    if (context.addListFile(userId, packageName, uri, subdomains)) {
                        navController.navigateBack()
                    }
                }
            }
        }
    RegularScaffold(
        title = stringResource(R.string.add_list),
        actions = {
            Button(
                onClick = {
                    val url = address.trim()
                    if (Uri.parse(url).let { it.scheme == "https" && !it.host.isNullOrEmpty() }) {
                        add(url, subdomains)
                    } else {
                        invalid = true
                    }
                },
                enabled = address.isNotBlank(),
            ) {
                Text(stringResource(R.string.add))
            }
        },
    ) {
        Category(title = stringResource(R.string.lists_suggested)) {
            for (suggestion in SuggestedList.entries) {
                if (suggestion.forAllApps != (packageName == null)) continue
                val isAdded = suggestion.url in added
                Preference(
                    object : PreferenceModel {
                        override val title = stringResource(suggestion.title)
                        override val summary = {
                            context.getString(
                                if (isAdded) R.string.list_added else suggestion.summary
                            )
                        }
                        override val enabled = { !isAdded }
                        override val onClick = { add(suggestion.url, suggestion.subdomains) }
                    }
                )
            }
            Preference(
                object : PreferenceModel {
                    override val title = stringResource(R.string.list_countries)
                    override val summary = { context.getString(R.string.list_countries_summary) }
                    override val onClick = CountryListsPageProvider.navigator(userId, packageName)
                }
            )
        }
        Category(title = stringResource(R.string.lists_own)) {
            SettingsOutlinedTextField(
                value = address,
                label = stringResource(R.string.list_address),
                errorMessage = if (invalid) stringResource(R.string.list_address_invalid) else null,
                placeholder = { Text(stringResource(R.string.list_address_hint)) },
            ) {
                address = it
                invalid = false
            }
            SwitchPreference(
                object : SwitchPreferenceModel {
                    override val title = stringResource(R.string.include_subdomains)
                    override val checked = { subdomains }
                    override val onCheckedChange: (Boolean) -> Unit = { subdomains = it }
                }
            )
            Preference(
                object : PreferenceModel {
                    override val title = stringResource(R.string.add_list_file)
                    override val summary = { context.getString(R.string.add_list_file_summary) }
                    // Any type, as lists come as text files of many kinds.
                    override val onClick = { openFile.launch(arrayOf("*/*")) }
                }
            )
        }
        Footer(stringResource(R.string.add_list_footer))
    }
}

/** Subscribes the scope to the list and downloads it; false, with a message, if it couldn't. */
internal suspend fun Context.addList(
    userId: Int,
    packageName: String?,
    url: String,
    subdomains: Boolean,
): Boolean {
    val id =
        try {
            Firewall.call { addList(userId, packageName, url, subdomains) }
        } catch (e: IllegalArgumentException) {
            Toast.makeText(this, R.string.list_add_failed, Toast.LENGTH_LONG).show()
            return false
        } catch (e: RemoteException) {
            Toast.makeText(this, R.string.list_add_failed, Toast.LENGTH_LONG).show()
            return false
        }
    if (id == null) {
        Toast.makeText(this, R.string.lists_full, Toast.LENGTH_LONG).show()
        return false
    }
    ListUpdates.checkNew(this)
    return true
}

/** Reads the file as a list and adds it for the scope; false, with a message, if it couldn't. */
private suspend fun Context.addListFile(
    userId: Int,
    packageName: String?,
    uri: Uri,
    subdomains: Boolean,
): Boolean {
    val message =
        try {
            val content =
                withContext(Dispatchers.IO) {
                    contentResolver.openInputStream(uri)?.use {
                        ListUpdates.read(this@addListFile, it, subdomains)
                    }
                }
            if (content == null) {
                R.string.list_file_failed
            } else {
                val title = withContext(Dispatchers.IO) { displayName(uri) } ?: uri.lastPathSegment
                val id =
                    content.use { file ->
                        ParcelFileDescriptor.open(file.file, ParcelFileDescriptor.MODE_READ_ONLY)
                            .use { fd ->
                                Firewall.call {
                                    addListFromFile(userId, packageName, title ?: "", fd)
                                }
                            }
                    }
                if (id == null) R.string.lists_full else null
            }
        } catch (e: IOException) {
            R.string.list_file_failed
        } catch (e: ListUpdates.ListException) {
            R.string.list_file_failed
        } catch (e: IllegalArgumentException) {
            R.string.list_file_failed
        } catch (e: RemoteException) {
            R.string.list_file_failed
        }
    if (message != null) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        return false
    }
    return true
}

private fun Context.displayName(uri: Uri): String? =
    contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
        if (it.moveToFirst()) it.getString(0) else null
    }
