##############################################
# OpenWrt Makefile for checking OS plc-gateway program
#
#
# Most of the variables used here are defined in
# the include directives below. We just need to
# specify a basic description of the package,
# where to build our program, where to find
# the source files, and where to install the
# compiled program on the router.
#
# Be very careful of spacing in this file.
# Indents should be tabs, not spaces, and
# there should be no trailing whitespace in
# lines that are not commented.
#
##############################################

include $(TOPDIR)/rules.mk

# Name and release number of this package
##############################################
# 2016.7.15 chenzejun change PKG_VERSION to 1.2.2
# 2016.8.23 chenzejun change PKG_VERSION to 1.3.2
# 2016.9.12 chenzejun change PKG_VERSION to 1.3.3, plc-gateway support lede and openwrt by one trunk.
##############################################
PKG_NAME:=plc-gateway
PKG_VERSION:=1.3.4
PKG_RELEASE:=1



#PKG_SOURCE_PROTO - the protocol to use for fetching the sources (git, svn)
#PKG_SOURCE_URL   - Where to download the sources from (directory)
#PKG_SOURCE_PROTO:=git
#PKG_SOURCE_URL=http://121.194.169.198:8888/chenzj/macscan.git
#PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
#PKG_SOURCE_VERSION:=c961d5bf14ec7b84ddbef2be0b5a1de1090a765a
#PKG_SOURCE_VERSION:=master
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz






PKG_MAINTAINER:=chenzejun <jack_chen_mail@163.com>
PKG_LICENSE:=GPL-3.0
PKG_LICENSE_FILES:=COPYING



# This specifies the directory where we're going to build the program. 
# The root build directory, $(BUILD_DIR), is by default the build_mipsel
# directory in your OpenWrt SDK directory
PKG_BUILD_PARALLEL:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)



include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

 

# Specify package information for this program.
# The variables defined here should be self explanatory.
# If you are running Kamikaze, delete the DESCRIPTION
# variable below and uncomment the Kamikaze define
# directive for the description below
define Package/plc-gateway
	SECTION:=utils
	CATEGORY:=Mypkg
	TITLE:=plc-gateway -- Support to the data collect for PLC
	DEPENDS:= +libpthread +libuci +libubox +libwl
endef


# Uncomment portion below for Kamikaze and delete DESCRIPTION variable above
define Package/plc-gateway/description
        If you can't figure out what this program does, you're probably
        brain-dead and need immediate medical attention.
endef

 

#TIMESTAMP:=$(shell date +%Y-%m-%d+%H:%M:%S)
#TARGET_CFLAGS +=-DPKG_RELEASE=\"$(PKG_RELEASE)\"
#TARGET_CFLAGS +=-DTIMESTAMP=\"${TIMESTAMP}\"
 
# Specify what needs to be done to prepare for building the package.
# In our case, we need to copy the source files to the build directory.
# This is NOT the default.  The default uses the PKG_SOURCE_URL and the
# PKG_SOURCE which is not defined here to download the source from the web.
# In order to just build a simple program that we have just written, it is
# much easier to do it this way.
define Build/Prepare
#	##echo "Here is Package/Prepare"
#	$(PKG_UNPACK)
#	rm -f $(DL_DIR)/$(PKG_SOURCE)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./* $(PKG_BUILD_DIR)/
endef


# Specify what needs to be done to Compile for building the package.
# How to compile the source; in most cases you should leave this undefined, 
# because then the default is used, which calls make. 
# If you want to pass special arguments to make, use e.g. "$(call Build/Compile/Default,FOO=bar)
#define Build/Compile
#	$(call Build/Compile/Default,PKG_RELEASE=$(PKG_RELEASE) TIMESTAMP=$(TIMESTAMP))
#endef

# We do not need to define Build/Configure or Build/Compile directives
# The defaults are appropriate for compiling a simple program such as this one


# Specify where and how to install the program. Since we only have one file,
# the check-v executable, install it by copying it to the /bin directory on
# the router. The $(1) variable represents the root directory on the router running
# OpenWrt. The $(INSTALL_DIR) variable contains a command to prepare the install
# directory if it does not already exist.  Likewise $(INSTALL_BIN) contains the
# command to copy the binary file from its current location (in our case the build
# directory) to the install directory.
define Package/plc-gateway/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/plc-gateway $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/plc-gateway.init $(1)/etc/init.d/plc-gateway
	$(INSTALL_DIR)	$(1)/etc/config
	$(CP) ./files/plc-gateway $(1)/etc/config
endef

# This line executes the necessary commands to compile our program.
# The above define directives specify all the information needed, but this
# line calls BuildPackage which in turn actually uses this information to
# build a package.
$(eval $(call BuildPackage,plc-gateway))