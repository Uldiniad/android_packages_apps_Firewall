/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.android.settingslib.spa.widget.dialog.AlertDialogButton
import com.android.settingslib.spa.widget.dialog.rememberAlertDialogPresenter
import com.android.settingslib.spa.widget.preference.TwoTargetButtonPreference
import kotlinx.coroutines.launch

/** Asks before removing a rule; returns what opens the question. */
@Composable
fun rememberRemoveRuleDialog(): (FirewallRule) -> Unit {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var rule by rememberSaveable { mutableStateOf<FirewallRule?>(null) }
    val dialog =
        rememberAlertDialogPresenter(
            confirmButton =
                AlertDialogButton(stringResource(R.string.remove)) {
                    val removed = rule ?: return@AlertDialogButton
                    scope.launch { Firewall.call { removeRules(arrayOf(removed)) } }
                },
            dismissButton = AlertDialogButton(stringResource(android.R.string.cancel)),
            title = rule?.let { stringResource(R.string.remove_rule_title, context.ruleTitle(it)) },
        )
    return {
        rule = it
        dialog.open()
    }
}

/** A rule's row, with a button that removes it. */
@Composable
fun RuleRow(rule: FirewallRule, remove: (FirewallRule) -> Unit) {
    val context = LocalContext.current
    val title = context.ruleTitle(rule)
    TwoTargetButtonPreference(
        title = title,
        summary = { context.ruleSummary(rule) },
        buttonIcon = Icons.Outlined.Delete,
        buttonIconDescription = stringResource(R.string.remove_rule_for, title),
        onButtonClick = { remove(rule) },
    )
}
