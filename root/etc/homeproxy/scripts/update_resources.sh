#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022-2023 ImmortalWrt.org

NAME="homeproxy"

RESOURCES_DIR="/etc/$NAME/resources"
mkdir -p "$RESOURCES_DIR"

RUN_DIR="/var/run/$NAME"
LOG_PATH="$RUN_DIR/$NAME.log"
mkdir -p "$RUN_DIR"

log() {
	echo -e "$(date "+%Y-%m-%d %H:%M:%S") $*" >> "$LOG_PATH"
}

to_upper() {
	echo -e "$1" | tr "[a-z]" "[A-Z]"
}

check_list_update() {
	local listtype="$1"
	local listrepo="$2"
	local listref="$3"
	local listname="$4"
	local wget="wget --timeout=10 -q"

	local list_info="$($wget -O- "https://api.github.com/repos/$listrepo/commits?sha=$listref&path=$listname")"
	local list_sha="$(echo -e "$list_info" | jsonfilter -e "@[0].sha")"
	local list_ver="$(echo -e "$list_info" | jsonfilter -e "@[0].commit.message" | grep -Eo "[0-9-]+" | tr -d '-')"
	if [ -z "$list_sha" ] || [ -z "$list_ver" ]; then
		log "[$(to_upper "$listtype")] Failed to get the latest version, please retry later."

		return 1
	fi

	local local_list_ver="$(cat "$RESOURCES_DIR/$listtype.ver" 2>"/dev/null" || echo "NOT FOUND")"
	if [ "$local_list_ver" = "$list_ver" ]; then
		log "[$(to_upper "$listtype")] Current version: $list_ver."
		log "[$(to_upper "$listtype")] You're already at the latest version."

		return 3
	else
		log "[$(to_upper "$listtype")] Local version: $local_list_ver, latest version: $list_ver."
	fi

	_TEMP_FILE="$RUN_DIR/._$(date '+%Y-%m-%d-%H-%M')-$(cat /proc/sys/kernel/random/uuid)_$listname"
	$wget "https://fastly.jsdelivr.net/gh/$listrepo@$list_sha/$listname" -O "$_TEMP_FILE"
	if [ $? -eq 0 ] && [ -s "$_TEMP_FILE" ]; then
 		mv -f "$_TEMP_FILE" "$RESOURCES_DIR/$listtype.${listname##*.}"
		echo -e "$list_ver" > "$RESOURCES_DIR/$listtype.ver"
		log "[$(to_upper "$listtype")] Successfully updated."
		return 0
  	else
		rm -f "$_TEMP_FILE"
		log "[$(to_upper "$listtype")] Update failed."
		return 1
	fi
 
}

case "$1" in
"china_ip4")
	check_list_update "$1" "1715173329/IPCIDR-CHINA" "master" "ipv4.txt"
	;;
"china_ip6")
	check_list_update "$1" "1715173329/IPCIDR-CHINA" "master" "ipv6.txt"
	;;
"gfw_list")
	check_list_update "$1" "Loyalsoldier/v2ray-rules-dat" "release" "gfw.txt"
	;;
"china_list")
	check_list_update "$1" "Loyalsoldier/v2ray-rules-dat" "release" "direct-list.txt" && \
		sed -i -e "s/full://g" -e "/:/d" "$RESOURCES_DIR/china_list.txt"
	;;
*)
	echo -e "Usage: $0 <china_ip4 / china_ip6 / gfw_list / china_list>"
	exit 1
	;;
esac
