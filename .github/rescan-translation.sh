#!/bin/bash

BASE_DIR="$(cd "$(dirname $0)"; pwd)"
LUCI_DIR="$BASE_DIR/../../luci"

if [ -d "$LUCI_DIR" ]; then
	perl "$LUCI_DIR/build/i18n-scan.pl" . > "$BASE_DIR/../po/templates/homeproxy.pot"
	perl "$LUCI_DIR/build/i18n-update.pl" "$BASE_DIR/../po"
else
	LUCI_URL="https://raw.githubusercontent.com/openwrt/luci/691574263356689912c5bd31984bb1b96417a847"
	perl <(curl -fs "$LUCI_URL/build/i18n-scan.pl") . > "$BASE_DIR/../po/templates/homeproxy.pot"
	perl <(curl -fs "$LUCI_URL/build/i18n-update.pl") "$BASE_DIR/../po"
fi
find "$BASE_DIR/../po" -name '*.po~' -delete;
