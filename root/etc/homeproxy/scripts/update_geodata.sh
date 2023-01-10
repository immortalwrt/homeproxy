#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022-2023 ImmortalWrt.org

NAME="homeproxy"

GEODATA_DIR="/etc/$NAME/resources"
GEOIP_REPO="1715173329/sing-geoip"
GEOSITE_REPO="1715173329/sing-geosite"
mkdir -p "$GEODATA_DIR"

RUN_DIR="/var/run/$NAME"
LOG_PATH="$RUN_DIR/$NAME.log"
LOCK="$RUN_DIR/update_geodata.lock"
mkdir -p "$RUN_DIR"

log() {
	echo -e "$(date "+%Y-%m-%d %H:%M:%S") $*" >> "$LOG_PATH"
}

check_multi_task() {
	if [ -e "$LOCK" ]; then
		log "A task is already running."
		exit 2
	else
		touch "$LOCK"
	fi
}

check_update() {
	local geotype="$1"
	local georepo="$2"
	local geotypeupper="$(to_upper "$geotype")"

	local geodata_ver="$(curl --connect-timeout 5 -fsSL "https://api.github.com/repos/$georepo/releases/latest" | jsonfilter -e "@.tag_name")"
	if [ -z "$geodata_ver" ]; then
		log "[$geotypeupper] Failed to get the latest version, please retry later."
		return 1
	fi

	local_geodata_ver="$(cat "$GEODATA_DIR/$geotype.db.ver" 2>"/dev/null" || echo "NOT FOUND")"
	if [ "$local_geodata_ver" = "$geodata_ver" ]; then
		log "[$geotypeupper] Current version: $geodata_ver."
		log "[$geotypeupper] You're already at the latest version."
		return 3
	else
		log "[$geotypeupper] Local version: $local_geodata_ver, latest version: $geodata_ver."
	fi

	local geodata_hash
	if curl --connect-timeout 5 -fsSL "https://github.com/$georepo/releases/download/$geodata_ver/$geotype.db" -o "$RUN_DIR/$geotype.db" && \
			geodata_hash="$(curl --connect-timeout 5 -fsSL "https://github.com/$georepo/releases/download/$geodata_ver/$geotype.db.sha256sum")"; then
		[ -z "$geodata_hash" ] || geodata_hash="$(echo "$geodata_hash" | awk '{print $1}')"
		if validate_sha256sum "$RUN_DIR/$geotype.db" "$geodata_hash"; then
			mv -f "$RUN_DIR/$geotype.db" "$GEODATA_DIR/$geotype.db"
			echo -e "$geodata_ver" > "$GEODATA_DIR/$geotype.db.ver"
			log "[$geotypeupper] Successfully updated."
			return 0
		fi
	fi

	rm -f "$RUN_DIR/$geotype.db"
	log "[$geotypeupper] Update failed."
	return 1
}

to_upper() {
	echo -e "$1" | tr "[a-z]" "[A-Z]"
}

validate_sha256sum() {
	local file="$1"
	local hash="$2"

	if [ ! -e "$file" ] || [ -z "$hash" ]; then
		return 1
	fi

	local filehash="$(sha256sum "$file" | awk '{print $1}')"
	if [ -z "$filehash" ] || [ "$filehash" != "$hash" ]; then
		return 1
	else
		return 0
	fi
}

case "$1" in
"get_version")
	for i in "geoip" "geosite"; do
		if [ ! -s "$GEODATA_DIR/$i.db.ver" ]; then
			info="${info:+$info<br/>}<strong style=\"color:red\">$(to_upper "$i"): NOT FOUND</strong>"
		else
			info="${info:+$info<br/>}<strong style=\"color:green\">$(to_upper "$i"): $(cat $GEODATA_DIR/$i.db.ver)</strong>"
		fi
	done
	echo -e "$info"
	;;
"update_version")
	check_multi_task

	check_update "geoip" "$GEOIP_REPO"
	ret1="$?"
	check_update "geosite" "$GEOSITE_REPO"
	ret2="$?"

	if [ "$2" = "update_subscription" ]; then
		lua "$GEODATA_DIR/../scripts/update_subscribe.lua"
	fi

	rm -f "$LOCK"

	if [ "$ret1" = "1" ] || [ "$ret2" = "1" ]; then
		exit 1
	elif [ "$ret1" = "0" ] || [ "$ret2" = "0" ]; then
		exit 0
	else
		exit 3
	fi
	;;
*)
	echo -e "Usage: $0 get_version | update_version <update_subscription>"
	exit 1
	;;
esac
