# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022-2023 ImmortalWrt.org

include $(TOPDIR)/rules.mk

LUCI_TITLE:=The modern ImmortalWrt proxy platform for ARM64/AMD64
LUCI_PKGARCH:=all
LUCI_DEPENDS:= \
	+sing-box \
	+firewall4 \
	+kmod-nft-tproxy \
	+ucode-mod-digest

PKG_NAME:=luci-app-canto

define Package/luci-app-canto/conffiles
/etc/config/canto
/etc/canto/certs/
/etc/canto/ruleset/
/etc/canto/resources/direct_list.txt
/etc/canto/resources/proxy_list.txt
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
