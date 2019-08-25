
module ("ktapi.ktUtil", package.seeall)

local util = require "luci.util"

function isLanLink(port)
	local cmd = 'swconfig dev switch0 show |grep "port:'..port..'"|grep "link:up"'
	local data = util.exec(cmd)

	if data == nil or data == "" then
		return 0
	else
		return 1
	end
end

function getSysInfo()
	return util.ubus("system", "info") or { }
end

function getBoardInfo()
	return util.ubus("system", "board") or { }
end

function getFirmwareInfo()
	local uci = require "luci.model.uci".cursor()
	local rv = {}

	rv["version"] = uci:get("firmwareinfo", "info", "firmware_version")

	-- use board type as the board name. for OEM.
	rv["board_name"] = util.exec("cat /tmp/sysinfo/board_type"):upper() or "unknown"

	return rv
end

function normalizeMac(mac)
	return string.lower(string.gsub(mac,"-",":"))
end

function officalMac(mac)
	return string.upper(string.gsub(mac,":",""))
end

function fork_exec(command)
	local pid = nixio.fork()
	if pid > 0 then
		return
	elseif pid == 0 then
		-- change to root dir
		nixio.chdir("/")

		-- patch stdin, out, err to /dev/null
		local null = nixio.open("/dev/null", "w+")
		if null then
			nixio.dup(null, nixio.stderr)
			nixio.dup(null, nixio.stdout)
			nixio.dup(null, nixio.stdin)
			if null:fileno() > 2 then
				null:close()
			end
		end

		-- replace with target command
		nixio.exec("/bin/sh", "-c", command)
	end
end

function firstLogin()
	local uci = require "luci.model.uci".cursor()

	if uci:get("system", "ntp", "initial") ~= nil then
		return true
	end

	return false
end