#
# SPDX-FileCopyrightText: The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
#

# Included by device/lineage/sepolicy when this repo is present.
ifeq ($(SOONG_CONFIG_lineage_firewall_enabled), true)
SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += \
    packages/apps/Firewall/sepolicy/private
endif
