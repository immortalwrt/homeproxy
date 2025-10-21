#!/bin/bash

BASE_DIR="$(cd "$(dirname $0)"; pwd)"
RESOURCES_DIR="$BASE_DIR/../root/etc/homeproxy/resources"

TEMP_DIR="$(mktemp -d -p $BASE_DIR)"

check_list_update() {
	local listtype="$1"
	local listrepo="$2"
	local listref="$3"
	local listname="$4"

	local list_info="$(gh api "repos/$listrepo/commits?sha=$listref&path=$listname&per_page=1")"
	local list_sha="$(echo -e "$list_info" | jq -r ".[].sha")"
	local list_ver="$(echo -e "$list_info" | jq -r ".[].commit.message" | grep -Eo "[0-9-]+" | tr -d '-')"
	if [ -z "$list_sha" ] || [ -z "$list_ver" ]; then
		echo -e "[${listtype^^}] Failed to get the latest version, please retry later."
		return 1
	fi

	local local_list_ver="$(cat "$RESOURCES_DIR/$listtype.ver" 2>"/dev/null" || echo "NOT FOUND")"
	if [ "$local_list_ver" = "$list_ver" ]; then
		echo -e "[${listtype^^}] Current version: $list_ver."
		echo -e "[${listtype^^}] You're already at the latest version."
		return 3
	else
		echo -e "[${listtype^^}] Local version: $local_list_ver, latest version: $list_ver."
	fi

	if ! curl -fsSL "https://raw.githubusercontent.com/$listrepo/$list_sha/$listname" -o "$TEMP_DIR/$listname" || [ ! -s "$TEMP_DIR/$listname" ]; then
		rm -f "$TEMP_DIR/$listname"
		echo -e "[${listtype^^}] Update failed."
		return 1
	fi

	mv -f "$TEMP_DIR/$listname" "$RESOURCES_DIR/$listtype.${listname##*.}"
	echo -e "$list_ver" > "$RESOURCES_DIR/$listtype.ver"
	echo -e "[${listtype^^}] Successfully updated."

	return 0
}

check_list_update "china_ip4" "1715173329/IPCIDR-CHINA" "master" "ipv4.txt"
check_list_update "china_ip6" "1715173329/IPCIDR-CHINA" "master" "ipv6.txt"
check_list_update "gfw_list" "Loyalsoldier/v2ray-rules-dat" "release" "gfw.txt"
check_list_update "china_list" "Loyalsoldier/v2ray-rules-dat" "release" "direct-list.txt" && \
	sed -i -e "s/full://g" -e "/:/d" "$RESOURCES_DIR/china_list.txt"

rm -rf "$TEMP_DIR"
