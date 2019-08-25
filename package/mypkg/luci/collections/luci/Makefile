#
# Copyright (C) 2008-2014 The LuCI Team <luci@lists.subsignal.org>
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk

LUCI_TYPE:=col
LUCI_BASENAME:=luci

LUCI_TITLE:=Standard OpenWrt set including full admin with ppp support and the default Bootstrap theme
LUCI_DEPENDS:= \
	+uhttpd +uhttpd-mod-ubus +luci-proto-ppp +libiwinfo-lua +IPV6:luci-proto-ipv6
	
define Build/Clean
	rm $(BUILD_DIR)/luci* -rf
endef

define Package/luci/install
	$(INSTALL_DIR) $(1)/etc/market/$(LUCI_BASENAME)
endef

include ../../luci.mk

# call BuildPackage - OpenWrt buildroot signature
