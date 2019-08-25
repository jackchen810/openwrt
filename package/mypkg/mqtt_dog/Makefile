##############################################
# OpenWrt Makefile for mqtt_dog program
# update log:
#
# 20170413:
#	0.0.4
#	release 2
#		add crontab, loop time is 30min
#		commit:d1c75c670c3f8ef5a62eb78e2a1bb80c8c916335
# 1.0.0
#	release 0 match mqtt-client 1.3.1 or newer
#		commit:53e6b6e006eee671e588f5be41b4ee6997e77074
#
# 1.0.1 release 0 gukq: 20170504 fix no id and error chekc bug
#		commit:0d90d215fd7aa8254f9a1e5c9b75cf082b93bc29
#
##############################################

include $(TOPDIR)/rules.mk

PKG_NAME:=mqtt_dog

PKG_VERSION:=1.0.1
PKG_RELEASE:=2

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=ssh://git@121.194.169.198:8022/kt-package/mqtt_dog.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
#PKG_SOURCE_VERSION:=master
PKG_SOURCE_VERSION:=5b67783a6a6ee52508d7ea543ddcb1a2a57d1294
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz


PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

TARGET_CFLAGS += -g

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=utils
	CATEGORY:=Mypkg
	TITLE:=mqtt_dog -- KT mqtt_dog mqtt-client monitor
	DEPENDS:= +mqtt-client
endef

# Uncomment portion below for Kamikaze and delete DESCRIPTION variable above
define Package/mqtt-client/description
        KT mqtt_dog mqtt-client monitor
endef

define Build/Prepare
	$(PKG_UNPACK)
	rm -f $(DL_DIR)/$(PKG_SOURCE) 
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/version_comp $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/mqtt_dog.sh $(1)/usr/sbin/
endef

define Package/$(PKG_NAME)/postinst
	#!/bin/sh
	[ -e $${IPKG_INSTROOT}/usr/sbin/mqtt_dog.sh ] && {
		$${IPKG_INSTROOT}/usr/sbin/mqtt_dog.sh init
	}
	exit 0
endef


$(eval $(call BuildPackage,$(PKG_NAME)))
