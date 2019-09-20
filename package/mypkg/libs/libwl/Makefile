##############################################
# OpenWrt Makefile for checking OS libwl program
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
# 2016.7.15 chenzejun change PKG_VERSION to 1.0.0
##############################################
PKG_NAME:=libwl
PKG_VERSION:=1.0.0
PKG_RELEASE:=1



#PKG_SOURCE_PROTO - the protocol to use for fetching the sources (git, svn)
#PKG_SOURCE_URL   - Where to download the sources from (directory)
#PKG_SOURCE_PROTO:=git
#PKG_SOURCE_URL=http://121.194.169.198:8888/chenzj/libwl.git
#PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
#PKG_SOURCE_VERSION:=60ebf44cff0eacd865b146a2e5f91f7725c5df63
#PKG_SOURCE_VERSION:=master
#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz






PKG_MAINTAINER:=chenzejun <chenzejun@kunteng.org>
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
define Package/libwl
	SECTION := libs
	CATEGORY := Mypkg
	SUBMENU := Librarys
	TITLE:=libwl -- Librarys
	DEPENDS:= +libuci +libubox
endef


# Uncomment portion below for Kamikaze and delete DESCRIPTION variable above
define Package/libwl/description
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

# 
# If your package provides a library that needs to be made available to other packages,
# you can use theBuild/InstallDevtemplate to copy it into the staging directory 
# which is used to collect all files that other packages might depend on at build time. 
# When it is called by the build system, two parameters are passed to it. 
# $(1)points to the regular staging dir, typically staging_dir/ ARCH, while $(2)points to staging_dir/host. 
# The host staging dir is only used for binaries
define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/libwl
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/include/*.h  $(1)/usr/include/libwl/
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/*.so* $(1)/usr/lib/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/*.a $(1)/usr/lib/
endef


# Specify where and how to install the program. Since we only have one file,
# the check-v executable, install it by copying it to the /bin directory on
# the router. The $(1) variable represents the root directory on the router running
# OpenWrt. The $(INSTALL_DIR) variable contains a command to prepare the install
# directory if it does not already exist.  Likewise $(INSTALL_BIN) contains the
# command to copy the binary file from its current location (in our case the build
# directory) to the install directory.
define Package/libwl/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/*.so* $(1)/usr/lib/
endef


# This line executes the necessary commands to compile our program.
# The above define directives specify all the information needed, but this
# line calls BuildPackage which in turn actually uses this information to
# build a package.
$(eval $(call BuildPackage,libwl))