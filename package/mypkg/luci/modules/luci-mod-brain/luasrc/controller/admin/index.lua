-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Licensed to the public under the Apache License 2.0.

module("luci.controller.admin.index", package.seeall)

function index()
	local root = node()
	if not root.target then
		root.target = alias("admin")
		root.index = true
	end

	local page   = node("admin")
	page.target  = firstchild()
	page.title   = _("Administration")
	page.order   = 10

	local loginpassword = luci.http.formvalue("wx") or ""
	if loginpassword == "" then
		page.sysauth = "root"
		page.sysauth_authenticator = "htmlauth"
	else
		if not luci.sys.user.checkpasswd("root", loginpassword) then
			luci.http.write("Incorrect password!")
			page.sysauth = "root"
			page.sysauth_authenticator = "jsonauth"
		end
	end

	page.ucidata = true
	page.index   = true

	local kt = require "ktapi.ktUtil"
	if kt.firstLogin() then
		entry({"admin", "first"}, template("wizard"),nil, 1)
	else
		entry({"admin", "first"}, template("home"),nil, 1)
	end

	entry({"admin", "home"}, template("home"),_("首页"), 1)
	entry({"admin", "wizard"}, template("wizard"),_("Wizard"),2)

	entry({"admin", "settings"}, firstchild(), _("设置"), 3)
	entry({"admin", "connect"}, firstchild(), _("连接"), 4)
	entry({"admin", "application"}, firstchild(), _("应用"), 5)
	entry({"admin", "wireless"}, firstchild(), _("无线"), 6)

	entry({"admin", "clients"}, firstchild(), _("设备管理"), 10).index = true
	entry({"admin", "clients", "connect_list"}, template("connect/connect"), _("连接设备"), 10)
	entry({"admin", "clients", "disabled_list"}, template("connect/disabledev"), _("禁用设备"), 20)
	entry({"admin", "clients", "printer_list"}, template("application/app_printer"), _("打印机管理"), 30)
	entry({"admin", "clients", "aisino_51box"}, template("application/app_aisino_51box"), _("51盒子管理"), 40)

	--entry({"admin", "clients", "wizard"}, template("wizard"),_("设置向导"),50)

	entry({"admin", "detection"}, firstchild(), _("环境检测"), 20).index = true
	entry({"admin", "detection", "fast_test"}, template("application/app_fast_test"), _("一键检测"), 10)
	entry({"admin", "detection", "net_diagnose"}, template("application/app_net_diagnose"), _("网络诊断"), 20)
	entry({"admin", "detection", "speed_test"}, template("application/app_speed_test"), _("网络测速"), 30)
	entry({"admin", "detection", "wifimon"}, template("application/app_wifimon"), _("WIFI环境检测"), 40)
	entry({"admin", "detection", "alarm"}, template("application/app_alarm"), _("报警通知"), 50)

	entry({"admin", "system"}, firstchild(), _("系统管理"), 30).index = true
	entry({"admin", "system", "sys_info"}, template("application/app_system_info"), _("系统信息"), 10).index = true
	entry({"admin", "system", "dev_reboot"}, template("application/app_auto_reboot"), _("重启系统"), 20).index = true
	entry({"admin", "system", "pppoe_log"}, template("application/app_pppoe_log"), _("拨号日志"), 30).index = true
	entry({"admin", "system", "password"}, template("settings/set_password"), _("修改密码"), 40).index = true

	entry({"admin", "network"}, firstchild(), _("网络设置"), 40).index = true
	entry({"admin", "network", "wan_settings"}, template("settings/set_wan"), _("上网设置"), 10).index = true
	entry({"admin", "network", "wifi_settings"}, template("settings/set_wifi"), _("无线设置"), 20).index = true
	entry({"admin", "network", "dhcp_settings"}, template("settings/set_dhcp"), _("DHCP设置"), 30).index = true
	entry({"admin", "network", "port_forward"}, template("application/app_port_forward"), _("端口映射"), 40).index = true
	-- entry({"admin", "network", "xfrp"}, template("application/app_xfrpc"), _("内网映射"), 50).index = true
	entry({"admin", "network", "syncdial"}, template("application/app_syncdial"), _("单线多拨"), 60).index = true
	entry({"admin", "network", "client_limit"}, template("connect/limiting"), _("限速设置"), 70).index = true

	entry({"admin", "logout"}, call("action_logout"), _("退出"), 90)
end

function action_logout()
	local dsp = require "luci.dispatcher"
	local utl = require "luci.util"
	local sid = dsp.context.authsession

	if sid then
		utl.ubus("session", "destroy", { ubus_rpc_session = sid })

		--dsp.context.urltoken.stok = nil

		luci.http.header("Set-Cookie", "sysauth=%s; expires=%s; path=%s/" %{
			sid, 'Thu, 01 Jan 1970 01:00:00 GMT', dsp.build_url()
		})
	end

	luci.http.redirect(luci.dispatcher.build_url())
end
