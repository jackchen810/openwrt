module("luci.controller.settings.index", package.seeall)

function index()
	local uci  = require "luci.model.uci".cursor()
	
	if (uci:get("network", "lan", "proto") ~= "dhcp") then
		entry({"admin", "settings", "wan"}, template("settings/set_wan"), _("上网设置"), 10).index = true
		entry({"admin", "settings", "lan"}, template("settings/set_lan"), _("内网设置"), 20).index = true
		entry({"admin", "settings", "dhcp"}, template("settings/set_dhcp"), _("DHCP设置"), 25).index = true
		entry({"admin", "settings", "mtu"}, template("settings/set_mtu"), _("MTU设置"), 30).index = true
	end
	
	entry({"admin", "settings", "wifi"}, template("settings/set_wifi"), _("无线设置"), 15).index = true
	entry({"admin", "settings", "password"}, template("settings/set_password"), _("修改密码"), 100).index = true
end
