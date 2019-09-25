include $(TOPDIR)/rules.mk

PKG_NAME:=own-base-files
PKG_VERSION:=1.1.1
PKG_RELEASE=1


PKG_BUILD_DIR:= $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=utils
	CATEGORY:=Mypkg
	TITLE:= own some base files
	DEPENDS:=+base-files
endef

define Package/$(PKG_NAME)/description
	The proccron is the daemon of  plugin.
endef

define Build/Prepare
    mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Compile/Default

endef
Build/Compile = $(Build/Compile/Default)

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/etc/crontabs
	$(CP) ./files/root  $(1)/etc/crontabs
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/procwatchdog.sh  $(1)/usr/sbin
	$(INSTALL_BIN) ./files/checkwan.sh  $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/firstboot.init $(1)/etc/init.d/firstboot
	$(INSTALL_BIN) ./files/firstboot.flag $(1)/etc/firstboot.flag
endef

# This line executes the necessary commands to compile our program.
# The above define directives specify all the information needed, but this
# line calls BuildPackage which in turn actually uses this information to
# build a package.
$(eval $(call BuildPackage,$(PKG_NAME)))
