#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2023 ImmortalWrt.org

SCRIPTS_DIR="/etc/homeproxy/scripts"

for i in "geoip" "geosite" "china_ip4" "china_ip6" "gfw_list" "china_list"
	"$SCRIPTS_DIR"/scripts/update_resources.sh
done

"$SCRIPTS_DIR"/scripts/update_subscribe.lua
