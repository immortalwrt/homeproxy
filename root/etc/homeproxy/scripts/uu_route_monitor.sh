#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022-2023 ImmortalWrt.org

NAME="homeproxy"
LOG_PATH="/var/run/$NAME/$NAME.log"

handle_route_event() {
	local line="$1"
	local action interface ip

	set -- $line

	if [ "$1" = "Deleted" ]; then
		# Example: "Deleted 172.19.163.0/24 dev tun163 proto kernel scope link src 172.19.163.1"
		ip="$2"
		interface="$4"
	elif [ "$2" = "via" ]; then
		# Example: "3.24.0.0/14 via 172.19.163.1 dev tun163 table 179"
		ip="$1"
		interface="$5"
		if [ "$1" = "8.8.8.8" ] || [ "$1" = "default" ]; then
			# Don't direct 8.8.8.8, uu always routes it
			# Skip "default via 172.19.163.1 dev tun163 table 163"
			return
		fi
	else
		return
	fi

	# Only handle uu tun interfaces
	case "$interface" in
		"tun163" | "tun164") ;;
		*) return ;;
	esac
	[ -n "$ip" ] || return

	local set_name="homeproxy_wan_uu_$interface"

	if [ "$1" = "Deleted" ]; then
		nft flush set inet fw4 "$set_name" 2>/dev/null
	else
		case "$interface" in
			"tun163")
				pending_tun163="${pending_tun163:+$pending_tun163, }$ip"
				;;
			"tun164")
				pending_tun164="${pending_tun164:+$pending_tun164, }$ip"
				;;
		esac
	fi
}

flush_pending() {
	if [ -n "$pending_tun163" ]; then
		nft add element inet fw4 homeproxy_wan_uu_tun163 "{ $pending_tun163 }" 2>/dev/null
		pending_tun163=""
	fi

	if [ -n "$pending_tun164" ]; then
		nft add element inet fw4 homeproxy_wan_uu_tun164 "{ $pending_tun164 }" 2>/dev/null
		pending_tun164=""
	fi
}

_cleanup() {
	pids=$(pgrep -P $$)

	for pid in $pids; do
		kill "$pid" 2>/dev/null
	done

 	exit
}

trap _cleanup TERM INT

ip monitor route | while true; do
	# Batch add elements for performance
	if read -t 1 line; then
		handle_route_event "$line"
	else
		flush_pending
	fi
done & wait $! # Receive TERM signal