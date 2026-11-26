/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import android.icu.text.Collator
import android.net.Uri
import android.os.Bundle
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Public
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavType
import androidx.navigation.navArgument
import com.android.settingslib.spa.framework.common.SettingsPageProvider
import com.android.settingslib.spa.framework.compose.navigator
import com.android.settingslib.spa.widget.preference.Preference
import com.android.settingslib.spa.widget.preference.PreferenceModel
import com.android.settingslib.spa.widget.preference.ZeroStatePreference
import com.android.settingslib.spa.widget.scaffold.SearchScaffold
import com.android.settingslib.spa.widget.ui.Footer
import com.android.settingslib.spa.widget.ui.LazyCategory
import java.util.Locale
import kotlinx.coroutines.launch

/**
 * Adds the list of a country's or region's IP addresses, for all of a user's apps or for one app,
 * as Firewalla's region blocking does; several can be added in a row.
 */
object CountryListsPageProvider : SettingsPageProvider {
    private const val USER_ID = "rt_userId"
    private const val PACKAGE_NAME = "rt_packageName"
    /** Stands for all of the user's apps in the route. */
    private const val ALL_APPS = "*"

    override val name = "CountryLists"

    override val parameter =
        listOf(
            navArgument(USER_ID) { type = NavType.IntType },
            navArgument(PACKAGE_NAME) { type = NavType.StringType },
        )

    @Composable
    fun navigator(userId: Int, packageName: String?) =
        navigator(route = "$name/$userId/${Uri.encode(packageName ?: ALL_APPS)}")

    @Composable
    override fun Page(arguments: Bundle?) {
        val args = checkNotNull(arguments)
        CountryListsPage(
            args.getInt(USER_ID),
            checkNotNull(args.getString(PACKAGE_NAME)).takeIf { it != ALL_APPS },
        )
    }
}

@Composable
private fun CountryListsPage(userId: Int, packageName: String?) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val lists by remember(userId) { Firewall.lists(userId) }.collectAsStateWithLifecycle(null)
    val added = lists.orEmpty().filter { it.packageName == packageName }.mapNotNull { it.url }
    val countries = remember { countriesByName() }
    SearchScaffold(title = stringResource(R.string.list_countries)) { bottomPadding, searchQuery ->
        val shown = countries.filter { it.second.contains(searchQuery(), ignoreCase = true) }
        LazyCategory(
            count = shown.size,
            key = { shown[it].first },
            bottomPadding = bottomPadding,
            header = {
                if (shown.isEmpty()) {
                    ZeroStatePreference(
                        Icons.Outlined.Public,
                        stringResource(R.string.list_countries_none),
                    )
                }
            },
            footer = { Footer(stringResource(R.string.list_countries_footer)) },
        ) { index ->
            val (country, name) = shown[index]
            val url = countryListUrl(country)
            val isAdded = url in added
            Preference(
                object : PreferenceModel {
                    override val title = name
                    override val summary = {
                        if (isAdded) context.getString(R.string.list_added) else ""
                    }
                    override val enabled = { !isAdded }
                    override val onClick: () -> Unit = {
                        scope.launch { context.addList(userId, packageName, url, true) }
                    }
                }
            )
        }
    }
}

/** The regions ipverse has no list for. */
private val UNLISTED = setOf("BV", "CC", "CX", "EH", "GS", "HM", "PN", "SH", "SJ", "TF", "UM")

/**
 * Every country and region ipverse has a list for, by its ISO code, with its name, in the order of
 * the names.
 */
private fun countriesByName(): List<Pair<String, String>> =
    Locale.getISOCountries()
        .filter { it !in UNLISTED }
        .map { it to countryName(it) }
        .sortedWith(compareBy(Collator.getInstance()) { it.second })
