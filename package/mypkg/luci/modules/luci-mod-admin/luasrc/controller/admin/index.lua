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
	page.sysauth = "root"
	page.sysauth_authenticator = "htmlauth"
	page.ucidata = true
	page.index = true

	local fs = require "nixio.fs"
	local uci  = require "luci.model.uci".cursor()

	--首次登陆强制访问设置向导, 瘦ap除外
	if fs.access("/usr/lib/lua/luci/firstlogin") and (uci:get("network", "lan", "proto") ~= "dhcp") then
		entry({"admin", "first"}, template("wizard"),nil, 1).index = true
	else
		entry({"admin", "first"}, template("home"),nil, 1).index = true
	end
	
	entry({"admin", "home"}, template("home"),_("Home"), 5).index = true
	entry({"admin", "wizard"}, template("wizard"),_("Wizard"), 10)
	
	entry({"admin", "network"}, template("network/net_wan"), _("Network"), 20).index = true
	entry({"admin", "wireless"}, template("wireless/wifi_settings"), _("Wireless"), 30).index = true
	entry({"admin", "advanced"}, firstchild(), _("Advanced"), 40).index = true
	entry({"admin", "system"}, firstchild(), _("System"), 50)
	entry({"admin", "application"}, firstchild(), _("Application"), 60)
	entry({"admin", "logout"}, call("action_logout"), _("Logout"), 90)
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
