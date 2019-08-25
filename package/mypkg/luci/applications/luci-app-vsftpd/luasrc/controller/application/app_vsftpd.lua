module("luci.controller.application.app_vsftpd", package.seeall)

function index()
	entry({"admin", "application", "vsftpd"}, template("application/app_vsftpd"), _("FTP服务器"), 64).index = true
	entry({"admin", "application", "vsftpd", "turnOffService"}, call("turnOffService"))
	entry({"admin", "application", "vsftpd", "getVsftpdStatus"}, call("getVsftpdStatus"))
	entry({"admin", "application", "vsftpd", "setVsftpd"}, call("setVsftpd"))
end

local uci = require "luci.model.uci".cursor()

function turnOffService()
	uci:set("vsftpd", "global", "enable", "0")
	uci:commit("vsftpd")

	luci.util.exec("/etc/init.d/vsftpd stop;killall -9 vsftpd")

	luci.http.prepare_content("application/json")
	luci.http.write_json({ code = 0 })
end

function getVsftpdStatus()
	local config = {}

	config["enable"] = uci:get("vsftpd", "global", "enable") or "1"
	config["port"] = uci:get("vsftpd", "global", "listen_port") or ""
	config["anony"] = uci:get("vsftpd", "global", "anonymous_enable") or ""
	config["anonyWrite"] = uci:get("vsftpd", "global", "anon_write_enable") or ""
	config["localRoot"] = uci:get("vsftpd", "global", "local_root") or ""
	config["anonRoot"] = uci:get("vsftpd", "global", "anon_root") or ""

	luci.http.prepare_content("application/json")
	luci.http.write_json(config)
end

function setVsftpd()
	local fs = require "nixio.fs"
	local json = require "luci.jsonc"
	local respData = {}
	local respCode = 0
	local accessDir = true
	local respMsg = ""

	local reqData = json.parse(luci.http.formvalue("reqdata"))

	if not fs.access(reqData.localRoot) then
		accessDir = false
		respMsg = "本地目录不存在."
		respCode = 1
	end

	if not fs.access(reqData.localRoot) then
		accessDir = false
		respMsg = "指定匿名访问的文件夹不存在."
		respCode = 1
	end

	if accessDir then
		uci:set("vsftpd", "global", "enable", 1)
		uci:set("vsftpd", "global", "listen_port", reqData.port)
		uci:set("vsftpd", "global", "local_root", reqData.localRoot)
		uci:set("vsftpd", "global", "anonymous_enable", reqData.anony)
		uci:set("vsftpd", "global", "anon_write_enable", reqData.anonyWrite)
		uci:set("vsftpd", "global", "anon_root", reqData.anonRoot)
		uci:commit("vsftpd")
	end

	if respCode == 0 then
		luci.util.exec("/etc/init.d/vsftpd restart")
	end

	respData["code"] = respCode
	respData["msg"] = respMsg
	luci.http.prepare_content("application/json")
	luci.http.write_json(respData)
end