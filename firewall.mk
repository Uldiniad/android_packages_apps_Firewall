#
# SPDX-FileCopyrightText: The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
#

PRODUCT_PACKAGES += \
    Firewall \
    FirewallFrameworksOverlay \
    firewall-service

PRODUCT_SYSTEM_SERVER_JARS += firewall-service

# Builds the firewall's policy in.
$(call soong_config_set_bool,lineage_firewall,enabled,true)
