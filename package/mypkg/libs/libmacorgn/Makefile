#########################################################
# Openwrt Makefile for Libktumi
# Created by gukaiqiang@kunteng.org 20160725
#
# This file include packages as fallows:
# 	libktumi
#	libktumi-st
#
# git-source :ssh://git@121.194.169.198:8022/kt-package/mac_orgn.git
# version record:
# 0.0.1:
#	The first release. 
# 	release2: using llx printformat instead of lx
#	release3: close DEBUG mode
#########################################################

include $(TOPDIR)/rules.mk

# Main Name and release number of this package
PKG_NAME := libmacorgn
PKG_VERSION := 0.0.3
PKG_RELEASE :=1


PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=ssh://git@121.194.169.198:8022/kt-package/libmacorgn.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
#PKG_SOURCE_VERSION:=master
#PKG_SOURCE_VERSION:=d8b4c631fdb9b3071bf95b466bb8089f585d9445
# debug mode
PKG_SOURCE_VERSION:=ea4d14b9981ece720354e3df8d559f132a1487ff
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz


# directory in your OpenWrt SDK directory
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)/$(PKG_NAME)-$(PKG_VERSION)
TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include

include $(INCLUDE_DIR)/package.mk

# directive for the description below
define Package/$(PKG_NAME)/Default
	SECTION := libs
	CATEGORY := Mypkg
	SUBMENU := Librarys
	TITLE := get the organization by mac-field
endef

define Build/Prepare
	$(PKG_UNPACK)
	rm -f $(DL_DIR)/$(PKG_SOURCE) 
endef

define Package/$(PKG_NAME)
	$(call Package/$(PKG_NAME)/Default)
endef


# Uncomment portion below for Kamikaze and delete DESCRIPTION variable above
define Package/$(PKG_NAME)/description
	get the organization by mac-field
endef


MACORGN_ST_MAKEOPTS= -C $(MACORGN_ST_BUILD_DIR) \
	CROSS_COMPILE="$(TARGET_CROSS)" 

#define Build/Prepare
#	mkdir -p $(PKG_BUILD_DIR)
#	$(CP) ./src/* $(PKG_BUILD_DIR)/
#endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/include/*.h  $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/*so $(1)/usr/lib/
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DIR) $(1)/usr/lib

	$(INSTALL_BIN) $(PKG_BUILD_DIR)/include/*.h  $(1)/usr/include/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/*so $(1)/usr/lib/
	
	$(INSTALL_DIR) $(1)/etc/mac_files
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/mac_files/* $(1)/etc/mac_files/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
