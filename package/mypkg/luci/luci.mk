#
# Copyright (C) 2008-2015 The LuCI Team <luci@lists.subsignal.org>
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

LUCI_NAME?=$(notdir ${CURDIR})
LUCI_TYPE?=$(word 2,$(subst -, ,$(LUCI_NAME)))
LUCI_BASENAME?=$(patsubst luci-$(LUCI_TYPE)-%,%,$(LUCI_NAME))
LUCI_LANGUAGES:=$(filter-out templates,$(notdir $(wildcard ${CURDIR}/po/*)))
LUCI_DEFAULTS:=$(notdir $(wildcard ${CURDIR}/root/etc/uci-defaults/*))
#LUCI_PKGARCH?=$(if $(realpath src/Makefile),,all)

# Language code titles

LUCI_LANG.en=English
LUCI_LANG.zh-cn=简体中文 (Chinese)

# Submenu titles
LUCI_MENU.col=1. Collections
LUCI_MENU.mod=2. Modules
LUCI_MENU.app=3. Applications
LUCI_MENU.theme=4. Themes
LUCI_MENU.proto=5. Protocols
LUCI_MENU.lib=6. Libraries
LUCI_MENU.oem=7. OEM


PKG_NAME?=$(LUCI_NAME)

PKG_VERSION?=$(if $(DUMP),x,$(strip $(shell \
	if svn info >/dev/null 2>/dev/null; then \
		revision="svn-r$$(LC_ALL=C svn info | sed -ne 's/^Revision: //p')"; \
	elif git log -1 >/dev/null 2>/dev/null; then \
		revision="svn-r$$(LC_ALL=C git log -1 | sed -ne 's/.*git-svn-id: .*@\([0-9]\+\) .*/\1/p')"; \
		if [ "$$revision" = "svn-r" ]; then \
			set -- $$(git log -1 --format="%ct %h"); \
			secs="$$(($$1 % 86400))"; \
			yday="$$(date --utc --date="@$$1" "+%y.%j")"; \
			revision="$$(printf 'git-%s.%05d-%s' "$$yday" "$$secs" "$$2")"; \
		fi; \
	else \
		revision="unknown"; \
	fi; \
		\
	ktver="$$(head "$(TOPDIR)"/package/kunteng/luci/ChangeLog -n 1 | cut -d " " -f 1)"; \
	kdate="$$(date "+%m%d")"; \
	revision="$$(printf '%s.%s' "$$ktver" "$$kdate")"; \
		\
	echo "$$revision" \
)))

PKG_GITBRANCH?=$(if $(DUMP),x,$(strip $(shell \
	variant="LuCI"; \
	if git log -1 >/dev/null 2>/dev/null; then \
		branch="$$(git symbolic-ref --short -q HEAD 2>/dev/null)"; \
		if [ "$$branch" != "master" ]; then \
			variant="LuCI $$branch branch"; \
		else \
			variant="LuCI Master"; \
		fi; \
	fi; \
	echo "$$variant" \
)))

PKG_RELEASE?=1
PKG_INSTALL:=$(if $(realpath src/Makefile),1)
PKG_BUILD_DEPENDS += lua/host luci-base/host $(LUCI_BUILD_DEPENDS)
PKG_CONFIG_DEPENDS += CONFIG_LUCI_SRCDIET CONFIG_LUCI_COMPILE

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_CLEAN_DIR:=$(shell rm $(PKG_BUILD_DIR) -rf)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=$(if $(LUCI_MENU.$(LUCI_TYPE)),$(LUCI_MENU.$(LUCI_TYPE)),$(LUCI_MENU.app))
  TITLE:=$(if $(LUCI_TITLE),$(LUCI_TITLE),LuCI $(LUCI_NAME) $(LUCI_TYPE))
  DEPENDS:=$(LUCI_DEPENDS)
  $(if $(LUCI_PKGARCH),PKGARCH:=$(LUCI_PKGARCH))
endef

ifneq ($(LUCI_DESCRIPTION),)
 define Package/$(PKG_NAME)/description
   $(strip $(LUCI_DESCRIPTION))
 endef
endif

# Language selection for luci-base
ifeq ($(PKG_NAME),luci-base)
 define Package/luci-base/config
   config LUCI_SRCDIET
	bool "Minify Lua sources"
	default n   
	
   config LUCI_COMPILE
	bool "Precompile Lua sources"
	default y

   menu "Translations"$(foreach lang,$(LUCI_LANGUAGES),

     config LUCI_LANG_$(lang)
	   tristate "$(shell echo '$(LUCI_LANG.$(lang))' | sed -e 's/^.* (\(.*\))$$/\1/') ($(lang))")

   endmenu
 endef
endif

define Build/Prepare
	for d in luasrc htdocs root src arch; do \
	  if [ -d ./$$$$d ]; then \
	    mkdir -p $(PKG_BUILD_DIR)/$$$$d; \
		$(CP) ./$$$$d/* $(PKG_BUILD_DIR)/$$$$d/; \
	  fi; \
	done
	$(call Build/Prepare/Default)
endef

define Build/Configure
endef

ifneq ($(wildcard ${CURDIR}/src/Makefile),)
 MAKE_PATH := src/
 MAKE_VARS += FPIC="$(FPIC)" LUCI_VERSION="$(PKG_VERSION)" LUCI_GITBRANCH="$(PKG_GITBRANCH)"

 define Build/Compile
	$(call Build/Compile/Default,clean compile)
 endef
else
 define Build/Compile
 endef
endif

HTDOCS = /www
LUA_LIBRARYDIR = /usr/lib/lua
LUCI_LIBRARYDIR = $(LUA_LIBRARYDIR)/luci
UCI_CONFIG = /etc/config

LUAC_OPTIONS = -s
define SrcCompile
	$(FIND) $(1) -type f -name '*.lua' | while read src; do \
		if ! $(STAGING_DIR_HOST)/bin/luac $(LUAC_OPTIONS) -o "$$$$src" "$$$$src"; \
		then echo "Error compiling $$$$src"; fi; \
	done
endef

define SrcDiet
	$(FIND) $(1) -type f -name '*.lua' | while read src; do \
		if $(STAGING_DIR_HOST)/bin/lua $(STAGING_DIR_HOST)/bin/LuaSrcDiet \
			--noopt-binequiv -o "$$$$src.o" "$$$$src"; \
		then mv "$$$$src.o" "$$$$src"; fi; \
	done
endef

define SubstituteVersion
	$(FIND) $(1) -type f -name '*.htm' | while read src; do \
		$(SED) 's/<%# *\([^ ]*\)PKG_VERSION *%>/\1$(PKG_VERSION)/g' \
		    -e 's/"\(<%= *\(media\|resource\) *%>[^"]*\.\(js\|css\)\)"/"\1?v=$(PKG_VERSION)"/g' \
			"$$$$src"; \
	done
endef

define Package/$(PKG_NAME)/install
	if [ -d $(PKG_BUILD_DIR)/luasrc ]; then \
	  $(INSTALL_DIR) $(1)$(LUCI_LIBRARYDIR); \
	  cp -pR $(PKG_BUILD_DIR)/luasrc/* $(1)$(LUCI_LIBRARYDIR)/; \
	  $(FIND) $(1)$(LUCI_LIBRARYDIR)/ -type f -name '*.luadoc' | $(XARGS) rm; \
	  $(if $(CONFIG_LUCI_SRCDIET),$(call SrcDiet,$(1)$(LUCI_LIBRARYDIR)/),true); \
	  $(call SubstituteVersion,$(1)$(LUCI_LIBRARYDIR)/); \
	  if [ "$(PKG_NAME)" != "luci-base" ]; then \
		$(if $(CONFIG_LUCI_COMPILE),$(call SrcCompile,$(1)$(LUCI_LIBRARYDIR)/),true); fi;\
	else true; fi
	if [ -d $(PKG_BUILD_DIR)/htdocs ]; then \
	  $(INSTALL_DIR) $(1)$(HTDOCS); \
	  cp -pR $(PKG_BUILD_DIR)/htdocs/* $(1)$(HTDOCS)/; \
	else true; fi
	if [ -d $(PKG_BUILD_DIR)/root ]; then \
	  $(INSTALL_DIR) $(1)/; \
	  $(call SrcCompile,$(PKG_BUILD_DIR)/root/); \
	  cp -pR $(PKG_BUILD_DIR)/root/* $(1)/; \
	else true; fi
	if [ -d $(PKG_BUILD_DIR)/src ]; then \
	  $(call Build/Install/Default) \
	  $(CP) $(PKG_INSTALL_DIR)/* $(1)/; \
	else true; fi
	if [ -d $(PKG_BUILD_DIR)/arch ]; then \
	  $(INSTALL_DIR) $(1)$(UCI_CONFIG); \
	  $(CP) $(PKG_BUILD_DIR)/arch/$(BOARD)/* $(1)/$(UCI_CONFIG)/; \
	else true; fi
endef

ifneq ($(LUCI_DEFAULTS),)
define Package/$(PKG_NAME)/postinst
[ -n "$${IPKG_INSTROOT}" ] || {$(foreach script,$(LUCI_DEFAULTS),
	(. /etc/uci-defaults/$(script)) && rm -f /etc/uci-defaults/$(script))
	exit 0
}
endef
endif


LUCI_BUILD_PACKAGES := $(PKG_NAME)

define LuciTranslation
  define Package/luci-i18n-$(LUCI_BASENAME)-$(1)
    SECTION:=luci
    CATEGORY:=LuCI
    TITLE:=$(PKG_NAME) - $(1) translation
    HIDDEN:=1
    DEFAULT:=LUCI_LANG_$(1)||(ALL&&m)
    DEPENDS:=$(PKG_NAME)
#    PKGARCH:=all
  endef

  define Package/luci-i18n-$(LUCI_BASENAME)-$(1)/description
    Translation for $(PKG_NAME) - $(LUCI_LANG.$(1))
  endef

  define Package/luci-i18n-$(LUCI_BASENAME)-$(1)/install
	$$(INSTALL_DIR) $$(1)/etc/uci-defaults
	echo "uci set luci.languages.$(subst -,_,$(1))='$(LUCI_LANG.$(1))'; uci commit luci" \
		> $$(1)/etc/uci-defaults/luci-i18n-$(LUCI_BASENAME)-$(1)
	$$(INSTALL_DIR) $$(1)$(LUCI_LIBRARYDIR)/i18n
	$(foreach po,$(wildcard ${CURDIR}/po/$(1)/*.po), \
		po2lmo $(po) \
			$$(1)$(LUCI_LIBRARYDIR)/i18n/$(basename $(notdir $(po))).$(1).lmo;)
  endef

  define Package/luci-i18n-$(LUCI_BASENAME)-$(1)/postinst
	[ -n "$$$${IPKG_INSTROOT}" ] || {
		(. /etc/uci-defaults/luci-i18n-$(LUCI_BASENAME)-$(1)) && rm -f /etc/uci-defaults/luci-i18n-$(LUCI_BASENAME)-$(1)
		exit 0
	}
  endef

  LUCI_BUILD_PACKAGES += luci-i18n-$(LUCI_BASENAME)-$(1)

endef

$(foreach lang,$(LUCI_LANGUAGES),$(eval $(call LuciTranslation,$(lang))))
$(foreach pkg,$(LUCI_BUILD_PACKAGES),$(eval $(call BuildPackage,$(pkg))))
