# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2022 ImmortalWrt.org

PKG_NAME:=luci-app-homeproxy
PKG_VERSION:=1.0
PKG_RELEASE:=$(AUTORELEASE)

LUCI_TITLE:=The modern ImmortalWrt proxy platform for ARM64/AMD64
LUCI_PKGARCH:=all
LUCI_DEPENDS:= \
	+sing-box \
	+sagernet-core \
	+curl \
	+lua-neturl

define Package/luci-app-homeproxy/conffiles
/etc/config/homeproxy
/etc/homeproxy/
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
