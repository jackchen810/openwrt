#
# Copyright (C) 2011-2013 OpenWrt.org
# Copyright (C) 2010 Jo-Philipp Wich <xm@subsignal.org>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# update log
# 	1705.1: add preinst and change ca.cert to read only
# 	1.4.5: add emqtt server
#  old version 1.4.7  is not compile； update to 1.6.6; but need libwebsockets version 2.1.0

include $(TOPDIR)/rules.mk

PKG_NAME:=mosquitto
PKG_VERSION:=1.6.6
PKG_RELEASE:=1705.1
PKG_LICENSE:=BSD-3-Clause
PKG_LICENSE_FILES:=LICENSE.txt



#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_SOURCE_URL:=https://mosquitto.org/files/source/
#PKG_MD5SUM:=529b6de33bac18363c2db46194d8d91c
#PKG_MD5SUM:=4cb978502312bff2dcdaab6a433b1bf2
#PKG_SOURCE_PROTO:=git
#PKG_SOURCE_URL:=ssh://git@121.194.169.198:8022/kt-package/mosquitto.git
#PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
#PKG_SOURCE_VERSION:=master
#PKG_SOURCE_VERSION:=89a57f11cdfec140fa21fe3d4493b2ca
#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

MAKE_FLAGS+=WITH_DOCS=no
MAKE_FLAGS+=WITH_WEBSOCKETS=$(if $(CONFIG_MOSQUITTO_LWS),"yes","no")

include $(INCLUDE_DIR)/version.mk
# The version of libopenssl in backfire doesn't support psk.
ifeq ($(findstring 10.03,$(VERSION_CODE)),10.03)
    MAKE_FLAGS += WITH_TLS_PSK=no
endif
# libopenssl prior to Barrier Breaker didn't support elliptic curve crypto
ifeq ($(findstring Attitude,$(VERSION_CODE)),Attitude)
    MAKE_FLAGS += WITH_EC=no
endif


define Package/$(PKG_NAME)/default
  CATEGORY:=Mypkg
  TITLE:=mosquitto - an MQTT message broker
  URL:=http://www.mosquitto.org/
  DEPENDS:= +librt +libuuid +libwebsockets
endef

# gukq 20161115 using libwebsockets instead of libwebsockets-openssl

define Package/$(PKG_NAME)
    $(call Package/mosquitto/default)
    TITLE+= (with SSL support)
    DEPENDS+= +libopenssl +MOSQUITTO_LWS:libwebsockets
    VARIANT:=ssl
endef

define Package/$(PKG_NAME)/config
	source "$(SOURCE)/Config.in"
endef

define Package/$(PKG_NAME)-nossl
    $(call Package/$(PKG_NAME)/default)
    TITLE+= (without SSL support)
    VARIANT:=nossl
endef

define Package/$(PKG_NAME)/default/description
 mosquitto is a message broker that supports v3.1 of the MQ Telemetry
Transport protocol. MQTT provides a lightweight method for
messaging using a publish/subscribe model.

This package also includes some basic support for configuring via UCI
endef

define Package/$(PKG_NAME)/description
	$(call Package/$(PKG_NAME)/default/description)
	This package is built with SSL support
endef

define Package/$(PKG_NAME)-nossl/description
        $(call Package/$(PKG_NAME)/default/description)
        This package is built WITHOUT SSL support.
endef

define Package/mosquitto-client/default
    $(Package/mosquitto/default)
    TITLE:= mosquitto - client tools
    DEPENDS+=+libcares
endef
define Package/mosquitto-client
    $(call Package/mosquitto-client/default)
    TITLE+= (With SSL support)
    DEPENDS+=+libmosquitto
    VARIANT:=ssl
endef
define Package/mosquitto-client-nossl
    $(call Package/mosquitto-client/default)
    TITLE+= (Without SSL support)
    DEPENDS+=+libmosquitto-nossl
    VARIANT:=nossl
endef

define Package/mosquitto-client/default/description
 Command line client tools for publishing messages to MQTT servers
and subscribing to topics.
endef

define Package/mosquitto-client/description
$(call Package/mosquitto-client/default/description)
        This package is built with SSL support
endef
define Package/mosquitto-client-nossl/description
$(call Package/mosquitto-client/default/description)
        This package is built without SSL support
endef

define Package/libmosquitto/default
    $(Package/mosquitto/default)
    SECTION:=libs
    CATEGORY:=Mypkg
	SUBMENU:=Librarys
    DEPENDS:=+libpthread +librt +libcares
    TITLE:= mosquitto - client library
endef

define Package/libmosquitto
    $(call Package/libmosquitto/default)
    TITLE+= (With SSL Support)
    DEPENDS+= +libopenssl
    VARIANT=ssl
endef
define Package/libmosquitto-nossl
    $(call Package/libmosquitto/default)
    TITLE+= (Without SSL Support)
    VARIANT=nossl
endef

define Package/libmosquitto/default/description
 Library required for mosquitto's command line client tools, also for
use by any third party software that wants to communicate with a
mosquitto server.

Should be useable for communicating with any MQTT v3.1 compatible
server, such as IBM's RSMB, in addition to Mosquitto
endef

define Package/libmosquitto/description
    $(call Package/libmosquitto/default/description)
    This package is built with SSL support
endef
define Package/libmosquitto-nossl/description
    $(call Package/libmosquitto/default/description)
    This package is built without SSL support
endef


define Package/$(PKG_NAME)/conffiles
/etc/mosquitto/mosquitto.conf
/etc/config/mosquitto
endef

Package/$(PKG_NAME)-nossl/conffiles = $(Package/$(PKG_NAME)/conffiles)

define Build/Prepare
#	$(PKG_UNPACK)
#	rm -f $(DL_DIR)/$(PKG_SOURCE) 
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/mosquitto-1.6.6/* $(PKG_BUILD_DIR)/
endef

define Package/$(PKG_NAME)/preinst
	#!/bin/sh
	[ -e $${IPKG_INSTROOT}/etc/config/mosquitto ] && {
		mv $${IPKG_INSTROOT}/etc/config/mosquitto $${IPKG_INSTROOT}/etc/config/mosquitto_old
	}

	exit 0
endef


define Package/$(PKG_NAME)/postinst
	#!/bin/sh
	[ -e $${IPKG_INSTROOT}/etc/mosquitto/yun-client.crt ] && {
		chmod 444 $${IPKG_INSTROOT}/etc/mosquitto/yun-client.crt
	}

	[ -e $${IPKG_INSTROOT}/etc/mosquitto/yun-client.ca ] && {
		chmod 444 $${IPKG_INSTROOT}/etc/mosquitto/yun-client.ca
	}
	
	[ -e $${IPKG_INSTROOT}/etc/init.d/mosquitto ] && {
		$${IPKG_INSTROOT}/etc/init.d/mosquitto restart
	}
	
	exit 0
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/mosquitto $(1)/usr/sbin/mosquitto
	$(INSTALL_DIR) $(1)/etc/mosquitto
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/mosquitto.conf $(1)/etc/mosquitto/mosquitto.conf
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/mosquitto.init $(1)/etc/init.d/mosquitto
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/mosquitto.uci.convert $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/mosquitto.config $(1)/etc/config/mosquitto
	$(INSTALL_CONF) ./files/yun-client.crt $(1)/etc/mosquitto/yun-client.crt
	$(INSTALL_CONF) ./files/yun-client.ca $(1)/etc/mosquitto/yun-client.ca
endef

Package/$(PKG_NAME)-nossl/install = $(Package/$(PKG_NAME)/install)


define Package/mosquitto-client/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/client/mosquitto_pub $(1)/usr/bin/mosquitto_pub
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/client/mosquitto_sub $(1)/usr/bin/mosquitto_sub
endef
Package/mosquitto-client-nossl/install = $(Package/mosquitto-client/install)

# This installs files into ./staging_dir/. so that you can cross compile from the host
define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/lib/mosquitto.h $(1)/usr/include
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/lib/libmosquitto.so.1 $(1)/usr/lib/
	$(LN) libmosquitto.so.1 $(1)/usr/lib/libmosquitto.so
endef

# This installs files on the target.  Compare with Build/InstallDev
define Package/libmosquitto/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/libmosquitto.so.1 $(1)/usr/lib/
	$(LN) libmosquitto.so.1 $(1)/usr/lib/libmosquitto.so
endef
Package/libmosquitto-nossl/install = $(Package/libmosquitto/install)

# Applies to all...
ifeq ($(BUILD_VARIANT),nossl)
        MAKE_FLAGS += WITH_TLS=no
endif

$(eval $(call BuildPackage,$(PKG_NAME)))
$(eval $(call BuildPackage,$(PKG_NAME)-nossl))
$(eval $(call BuildPackage,libmosquitto))
$(eval $(call BuildPackage,libmosquitto-nossl))
$(eval $(call BuildPackage,mosquitto-client))
$(eval $(call BuildPackage,mosquitto-client-nossl))
