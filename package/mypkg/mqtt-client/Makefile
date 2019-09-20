##############################################
# OpenWrt Makefile for mqtt-client program
#
# gukq 20161116: the latest version published by victor is 
#	PKG_VERSION:=0.1.8
#	PKG_SOURCE_VERSION:=fea9e1507ff11b837297f1e52d2ee95d9718516a
# 	the first version published by gukq is 
#	PKG_VERSION:=1.0.0
# 	PKG_SOURCE_VERSION:=80d188ba0cb546939cd82f5e7d50267ec45943d0
#
# version record:
#
# 1.0.4 rewrite ExecuateShellCMD and add timeout to ExecuateShellCMD func
# 	at PKG_RELEASE 106 to modify std-popen.
#
# 	release 129 is ok version with 3.5min timeout.
# 	release 132 add mqtt_timeout file to contrl timeout seconds.
#	release 146 mqtt_client EGEND trytimes up to 200 times, and fix 
#		bug of return succeed when BASH execed failed error.
#
# 1.1.0 add netinfo/lan_net_opt/lan_dhcp_opt/wifidog_mode_opt interface.
# 	release 30: first stable release for HongHer project
#
# 1.1.1 fix the bug #ROM-864: no channel_path info after image upgraded.
#
# 1.1.2 add auto_server_send func to send some info to sesrver at once 
#	mqtt_client start
# 1.1.3 restart dnsmasq after change lan-gateway IP address. And go on 
# 	handle ROMSYNC issue
# 1.1.4 hong he 20170210 version
# 1.1.5 20170213 fix double mqtt-client pid error
# 1.1.6 20170214 add firmware-file checking before do sysupgrade
#
# 	release 18 PASSED the firmware-upgrade test checking version rc1
#	release [28] fix some bugs:#ROM-977 #ROM-978 #ROM-979 #ROM-980
#	release [30] commit:f02895466652d34918b3d19ce6802f3b8e21feb8 fix 
#		double board_type bug. Used for JPM-oem 20170217
#	release 31 add ROM_SYNC hearbeat per Hour
#	release 36 20170220 fix bug #ROM-984, fix bug #ROM-975 and restart
#		dnsmasq after doing dhcp-range set. Updated the client 
#		protocol version 1.1.0. 
#		commit:50d0d2ed74c2a3474064320b7ea2a48b50ef0653
#
# 1.2.0 20170223 add "wireless_if_opt" interface into CMD_EXE commands-set
#
# 	release 21 uing popen_no_shell instead of pipi exec to fix double 
#		mqtt-client pid
#	release 27 using old popen, and using curl lib interface instead of
#		wget cmd 
#		commit:597843c3a094a9870ac11d4428fcd3624fd5563c
#	release 29 add curl lib for download tool, tested to haolijin for 
#		honghe
#		commit:7a3bfb08b3854644b13a7ef73bfd7e8e302d7c69
#	release 44 using curl instead of wget, first test version with yinyin
#		commit:300264f8b510ff7de09560c56f24905fadcfe393
#	release 47 commit:0a5792ca16fcbd026bcec4d9a99d2961ddce5b34
#		set download outtime to 600s.
#
# 1.2.1 20170307 fix #ROM-1054:add "channel_path" in sysinfo;
#	 	fix #ROM-985: add s_sleep after network restart
#	release 5 commit:b0d45f32e6b34992679c59f72f83dad56980e29e 
#		resolve the issue
#
# 1.2.2 20170315
# 	release 7 commit:5e5536f7ad368df9a208611f1f4b9839754e2d02
#		fix #ROM-1074
#	release 12 commit:7fd597263a1f1e7dd972a01a1c4c294a72d56fc7
#		fix wireless get failed error
#	release 17 add sleep in EXE and SET
#		add mosquitto_publish return debug info
#		commit:9e29183ca1061bb9b4eb64416de89334e255db4c
#	release 19 fix cmd bug
#		commit:b2696379deedbdfb99b2a612e276f04185193d48
#	release 24 don't sleep after handle cmds
#		commit:d81f61553bdf00754a8810c0e8ecdbe6585779d3
# 1.2.3 20170322 
# 	release 40 no strcpy, no sprintf, add timeout with popen
#		this will kill all Z childpids and timeout-child
#		pids
#		commit:46d810c0a29326812e5af46531b60ef1fdc4010a
#	release 41 timeout 400s
#		commit:a529f39a12e045b0d32e213349a202d95a1abb63
#	release 44 remove  json_put in
#		commit:20a224e7fc876c6fe8f566156f43224ee5c7bb4f
#	release 75 stable version 1
# 		commit:62e3d19f5a45288807808fe579da7410f9c35c0b
#	release 80 check all json / goto method
#		commit:df957b071ad43efa05479beccdf84c91a179196a
#	release 82 check again, remove some log. set log max 
#		size to 512K
#		commit:27c7cbeba23c37da61df34d259565d501a66b5c4
#	release 84 set init qos to 0; fixed bug #ROM-1135
#		commit:7f9abfb87779e03e31751c452cf007b88e1bc32d
#	release 86 fix parse id field error
#		commit:1751d8aead30aad6184685602046fb7faa585105
# 1.2.4 20170417 
# 	release 0 add get_net_speed_addr interface
#		commit:7fdeec6f7cc7b546b6574858ba286ce18d7af9c2
#
# 1.3.0 20170420 
# 	release 5 do not open cmd_shell interface for everybody
#		commit:a7e792801ee1106d674d4326a4266767e2e5fde6
#	release 15 0424 version
#		commit:537229609dc3b2d70d6e2512361d77b707105a42
#	release 16 debug item return net_speed_addr instead of 
#		curl_addr
#		commit:744bd8a7b254f79321e5536ed67e8120bc9caa2b
# 1.3.1 20170425 add mqtt ping pong interface
#	release 0 commit:6947b90d229c92e40469b3e4c1a13bf10ed86fef
#
# 1.3.2 20170426 add url_opt interface
#	release 1 url and response neeb standerd base64 encode
#		commit:7ffead276d369d92b8dbb8664005f43479cb3115
#	release 2 add pong field in mqtt-ping interface
#		commit:4368b9264070027af918c141718fb3d910755dc2
#	release 5 add passwd_verify and remove some DEBUG print
#		commit:2d3b87e1bbb3ab65c32c65e30f9364970c3c6ca6
#
# 1.3.3 20170504 add reproxy interface
#	release 0 commit:c4b4798d019e846f58940263b9e2f731cb6eab2d
#	release 4 gukq complate reproxy interface
#		commit:10edcf724fe61aaad483d4a9c2c5805ba4938673
#	release 5 add frpc stop func
#		commit:f8fa1c24580fee804d34490b5102588d3e6badd0
#	release 6 add protocol modify
# 		commit:8aae563f1f6da87d8cc6e7211910e0b270ea7831
#	release 7 debug ROM-1180 using lan-gateway-reload instead 
#		of network restart
#		commit:8abe615e3878a5b6d6d05679443429ff52b4a124
#	release 8 fix ROM-1184
#		commit:c88074b5aeac0848804251b83d0e0bcae9293cde
#	release 11 add mycurl https support
#		commit:97e61d4d2cf938f3e01194ef3d1322b5753633cc
#	release 15 fix url base64 decode bug
#		commit:11dd5c89e8921a64355923a1a5a091a4fd134338
#	release 17 20170904 fix wireless set failed in wireless
#		CMDEXE.fix bug ROM-1321
#		commit:18f17680fbcc9eaf261a105ae079e2e945ed28d3
#
# 1.3.4 20170904 add trackmon interfaces
#	release 2 add trackmon_data interface
#		commit:a4b536303a494998ad99b0071857e02b89181b1f
#	release 18 20180621 use latest code
#		commit:abdcd07dd106405b5af239a31e9999d4617874e7
##############################################

include $(TOPDIR)/rules.mk

PKG_NAME:=mqtt-client

PKG_VERSION:=2.0.0
PKG_RELEASE:=2.0.0

#PKG_SOURCE_PROTO:=git
#PKG_SOURCE_URL:=ssh://git@121.194.169.198:8022/kt-package/mqtt-client.git
#PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
#PKG_SOURCE_VERSION:=master
#PKG_SOURCE_VERSION:=abdcd07dd106405b5af239a31e9999d4617874e7
#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz


PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

TARGET_CFLAGS += -g

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=utils
	CATEGORY:=Mypkg
	TITLE:=mqtt-client -- mqtt-client
	DEPENDS:= +libmosquitto +libjson-c +libpthread +libuci +libcurl
endef

# Uncomment portion below for Kamikaze and delete DESCRIPTION variable above
define Package/mqtt-client/description
        mqtt client tools for IOT
endef

define Build/Prepare
	#$(PKG_UNPACK)
	#rm -f $(DL_DIR)/$(PKG_SOURCE) 
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef


define Package/$(PKG_NAME)/preinst
	#!/bin/sh
	[ -e $${IPKG_INSTROOT}/usr/sbin/wanset.lua ] && {
		rm -rf $${IPKG_INSTROOT}/usr/sbin/wanset.lua
	}

	[ -e $${IPKG_INSTROOT}/usr/sbin/checkpasswd ] && {
		rm -rf $${IPKG_INSTROOT}/usr/sbin/checkpasswd
	}
	
	[ -e $${IPKG_INSTROOT}/usr/sbin/setpasswd ] && {
		rm -rf $${IPKG_INSTROOT}/usr/sbin/setpasswd
	}
	
	[ -e $${IPKG_INSTROOT}/usr/sbin/wanset.lua ] && {
		rm -rf $${IPKG_INSTROOT}/usr/sbin/wanset.lua
	}
	
	[ -e $${IPKG_INSTROOT}/usr/sbin/blist ] && {
		rm -rf $${IPKG_INSTROOT}/usr/sbin/blist
	}

	exit 0
endef


define Package/$(PKG_NAME)/postinst
	#!/bin/sh
	[ -e $${IPKG_INSTROOT}/etc/init.d/$(PKG_NAME) ] && {
		$${IPKG_INSTROOT}/etc/init.d/$(PKG_NAME) restart
	}
	exit 0
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mqtt-client $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/kt_wireless_op.lua $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/qos_opt.lua $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/checkpasswd $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/setpasswd $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/wanset.lua $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/blist.sh $(1)/usr/sbin/blist
	
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/mqtt-client.init $(1)/etc/init.d/mqtt-client
	
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) ./files/mqtt-client.conf $(1)/etc/config/mqtt-client
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
