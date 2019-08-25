module("luci.controller.application.app_shadowsocks", package.seeall)

function index()
	local opkg = require "luci.model.ipkg"
	local packageName = "shadowsocks-libev"

	if opkg.status(packageName)[packageName] then
		entry({"admin", "application", "shadowsocks"}, template("application/app_shadowsocks"), _("Shadowsocks"), 60).index = true
		entry({"admin", "application", "shadowsocks", "setShadowsocks"}, call("setShadowsocks"))
		entry({"admin", "application", "shadowsocks", "turnOffService"}, call("turnOffService"))
		entry({"admin", "application", "shadowsocks", "updateGFWList"}, call("updateGFWList"))
	end
end

local uci = require "luci.model.uci".cursor()

function setShadowsocks()
	local json = require "luci.jsonc"
	local fs = require "nixio.fs"
	local cs = "/usr/local/shadowsocks/custom.txt"

	local r = json.parse(luci.http.formvalue("reqdata"))

	uci:set("shadowsocks", "proxy", "disabled", "0")
	uci:set("shadowsocks", "proxy", "udp_relay", r.UdpRelay)

	uci:set("shadowsocks", "proxy", "proxy_mode", r.ProxyType)
	if r.Gfwlist then
		uci:set("shadowsocks", "proxy", "gfwlist", r.Gfwlist)
	end

	if r.Custom then
		uci:set("shadowsocks", "proxy", "custom", r.Custom)
	end

	uci:set("shadowsocks", "server", "address", r.Server)
	uci:set("shadowsocks", "server", "port", r.Port)
	uci:set("shadowsocks", "server", "encryption", r.Encrypt)
	uci:set("shadowsocks", "server", "password", r.PassWord)

	uci:commit("shadowsocks")

	if not r.CustomList then r.CustomList = "" 	end
	fs.writefile(cs, r.CustomList)

	luci.util.exec("/etc/init.d/shadowsocks restart")

	luci.http.prepare_content("application/json")  
	luci.http.write_json({ code = 0 })
end

function turnOffService()
	uci:set("shadowsocks", "proxy", "disabled", "1")
	uci:commit("shadowsocks")

	luci.util.exec("/etc/init.d/shadowsocks stop")

	luci.http.prepare_content("application/json")
	luci.http.write_json({ code = 0 })
end

function updateGFWList()
	local ktUtil = require "ktapi.ktUtil"
	local respDate = {}
	local respCode = 0

	local ac = luci.http.formvalue("action")

	if ac == "1" then
		respCode = ((luci.util.exec("pidof shadowsocks") == "") and 1 or 0)
	else
		ktUtil.fork_exec("/etc/init.d/shadowsocks update")
	end

	respDate["code"] = respCode
	respDate["ver"]	 = luci.util.exec("head -n 1 /usr/local/shadowsocks/gfwlist.conf| cut -d \" \" -f 2,4,5")

	luci.http.prepare_content("application/json")  
	luci.http.write_json(respDate)
end