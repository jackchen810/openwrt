include $(TOPDIR)/rules.mk

PKG_NAME:=frpc
PKG_VERSION:=0.29.0
PKG_RELEASE=1


PKG_BUILD_DIR:= $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=utils
	CATEGORY:=Mypkg
	TITLE:= frp is a reverse proxy to access your computer in LAN by SSH. 
	DEPENDS:=
endef

define Package/$(PKG_NAME)/description
	The client of the frp.
endef

define Build/Prepare
    mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Compile/Default

endef
Build/Compile = $(Build/Compile/Default)

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/frpc  $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_BIN) ./files/frpc.ini  $(1)/etc
	$(INSTALL_BIN) ./files/frpc_full.ini  $(1)/etc
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/frpc.init $(1)/etc/init.d/frpc
endef

# This line executes the necessary commands to compile our program.
# The above define directives specify all the information needed, but this
# line calls BuildPackage which in turn actually uses this information to
# build a package.
$(eval $(call BuildPackage,$(PKG_NAME)))
