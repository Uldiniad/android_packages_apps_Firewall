/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

/** An app's rules for one user. */
parcelable AppRule {
    String packageName;
    int rules;
}
