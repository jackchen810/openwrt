module("luci.controller.application.app_samba", package.seeall)

function index()
		entry({"admin", "application", "samba"}, template("application/app_samba"), _("文件共享"), 63).index = true
		entry({"admin", "application", "setSambaShare"}, call("setSambaShare"))
		entry({"admin", "application", "delSambaShare"}, call("delSambaShare"))
end

local uci  = require "luci.model.uci".cursor()

function delSambaShare()
	local rspData = {}
	local codeResp = 1

	local name = luci.http.formvalue("name")

	if _deleteSambaShare(name) then 
		codeResp = 0
		uci:commit("samba")
	end

	rspData["code"] = codeResp

	luci.util.exec("/etc/init.d/samba restart")
	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end

function setSambaShare()
	local rspData = {}
	local codeResp = 1

	local path		= luci.http.formvalue("path")
	local name		= luci.http.formvalue("name")
	local readOnly	= luci.http.formvalue("readOnly")
	local guest		= luci.http.formvalue("guest")
	local desc		= luci.http.formvalue("description")

	local codeResp = _setSambaShare(name, path, readOnly, guest, desc)

	rspData["code"] = codeResp

	luci.util.exec("/etc/init.d/samba restart")
	luci.http.prepare_content("application/json")
	luci.http.write_json(rspData)
end

function _deleteSambaShare(name)
	local result = false

	uci:foreach("samba", "sambashare",
		function(s)
			if s.name == name then
				uci:delete("samba", s[".name"])
				result = true
			end
		end)

	return result
end

function _nameConflictCheck(name)
	local result = nil
	uci:foreach("samba", "sambashare",
		function(s)
			if s.name == name then
				result = s[".name"]
			end
		end
	)
	return result
end

function _setSambaShare(name, path, readOnly, guest, desc)
	if _nameConflictCheck(name) ~= nil then
		return 2
	end

	local options = {
		["name"]		= name or "",
		["path"]		= path,
		["read_only"]	= readOnly,
		["guest_ok"]	= guest,
		["description"] = desc or "",
	}

	uci:section("samba", "sambashare", nil, options)
	uci:commit("samba")
	return 0
end