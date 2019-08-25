module ("ktapi.ktClient", package.seeall)

function ktprivTable()
	local util	= require "luci.util"
	local data = {}
	local k = { "mac address", "mac type", "is local", "port_no", "ageing timer" }
	local ps = util.execi("ktpriv get_mac_list -v")

	if not ps then
		return
	else
		ps()
	end

	for line in ps do
		local row = {}
		local j = 1

		for value in line:gmatch("[^%s]+") do
			row[k[j]] = value
			j = j + 1
		end

		if row[k[1]] then

			if not row[k[2]] then
				j = 2
				line = ps()

				for value in line:gmatch("[^%s]+") do
					row[k[j]] = value
					j = j + 1
				end

			end

			table.insert(data, row)
		end
	end

	return data
end

function getClientList()
	local status	= require "luci.tools.status"
	local util		= require "luci.util"

	local onlineDeviceList = {}
	local clientListResp = {}
	local hostNameHash = {}
	local ipAddrHash = {}
	local dhcpLeases = {}

	local macaddr, ipaddr, hostname, connmode

	onlineDeviceList = ktprivTable()
	dhcpLeases = status:dhcp_leases()

	for _, user in ipairs(dhcpLeases) do
		hostNameHash[user['macaddr']] = ((user["hostname"] == false) and "" or user["hostname"])
		ipAddrHash[user['macaddr']] = user['ipaddr']
	end

	-- 过滤在线设备列表
	if onlineDeviceList then
		for _, net in ipairs(onlineDeviceList) do

			if net['is local'] ~= "yes" then
				macaddr = net['mac address']

				if hostNameHash[macaddr] ~= nil and hostNameHash[macaddr] ~= "" then
					hostname = hostNameHash[macaddr]
				else
					hostname = "unknown"
				end

				-- 判断1, 防止列表有相同mac地址
				if ipAddrHash[macaddr] ~= nil and ipAddrHash[macaddr] ~= "" and ipAddrHash[macaddr] ~= 1 then
					ipaddr = ipAddrHash[macaddr]

					-- 标识mac在线
					ipAddrHash[macaddr] = 1
				else
					ipaddr = util.exec("ktpriv get_ip_by_mac " .. macaddr)
				end

				if net['mac type'] == "NA" then net['mac type'] = "2.4G" end
				--connmode = ((tonumber(util.exec("ktpriv get_mac_source "..macaddr)) == 1) and "wireless" or "wired")
				connmode = net['mac type']

				table.insert(clientListResp, {
					['ipaddr'] = ipaddr:match("(%S+)\n") or ipaddr,
					['macaddr'] = string.lower(macaddr),
					['mac_source'] = connmode,
					['hostname'] = hostname
				})
			end
		end
	end

	-- 离线设备列表
	for _, user in ipairs(dhcpLeases) do
		if ipAddrHash[user['macaddr']] ~= 1 then
			table.insert(clientListResp, {
				['ipaddr'] = user['ipaddr'],
				['macaddr'] =  string.lower(user['macaddr']),
				['mac_source'] = "offline",
				['hostname'] = ((user["hostname"] == false) and "unknown" or user["hostname"])
			})
		end
	end

	return clientListResp
end

function wifiStaTable()
	local util	= require "luci.util"
	local data = {}

	local function _doListStaCommand(command, t)
		local cmd = util.execi(command)
			if not cmd then
				return
			else
				cmd()
			end

			for line in cmd do
				if macType(line) then 
					table.insert(t, {line = true})
				end
			end
		return t
	end

	local sysClassNet = util.execl("ls /sys/class/net")

	for _, n in ipairs(sysClassNet) do

		if n:match('^ath') == "ath" then
			data = _doListStaCommand('wlanconfig %q list sta | cut -d " " -f 1' % n, data)
		elseif 
			n:match('^ra') == "ra" then
			data = _doListStaCommand('iwpriv %q get_mac_table | cut -d " " -f 1' % n, data)
		end
	end

	return data
end

function macType(val)
	local util	= require "luci.util"

	if val and val:match(   
			"^[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+:" ..
			"[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+$"
		) then
		local parts = util.split( val, ":" )

		for i = 1,6 do
			parts[i] = tonumber( parts[i], 16 )
			if parts[i] < 0 or parts[i] > 255 then
				return false
			end
		end

		return true
	end

	return false
end

function getClientNum()
	local deviceResp = {}
	local c = 0

	deviceResp = ktprivTable()
	if deviceResp then
		for _, net in ipairs(deviceResp) do
			if net['is local'] ~= "yes" then
				c = c + 1
			end
		end
	end

	return c
end

-- IP=192.168.199.123   session_quota=0  upload_quota=0  download_quota=0  session=0 upload_bytes=899275 download_bytes=20658156 upload_rate=90  download_rate=250 
function getTigerIpStat()
	local data = {}
	local qosfile = "/proc/net/tiger_ip_stat"

	local fd = io.open(qosfile, "r")
	if fd then
		while true do
			local ln = fd:read("*l")
			if not ln then
				break
			else
				local ip, sq, uq, dq, ss, ub, db, ur, dr = ln:match("IP=(%S+).+=(%S+).+=(%S+).+=(%S+).+=(%S+).+=(%S+).+=(%S+).+=(%S+).+=(%S+)")
				if ip and uq and dq and ur and dr then
					data[ip] = {
						upload_quota = uq,
						download_quota = dq,
						upload_rate = ur,
						download_rate = dr
					}
				end
				-- print(ip, sq, uq, dq, ss, ub, db, ur, dr)
			end
		end
		fd:close()
	end

	return data
end

function getEthersInfo()
	local data = {}
	local filepath = "/etc/ethers"
	local mask, ipaddr, macaddr

	local fd = io.open(filepath, "r")
	if fd then
		while true do
			local lns = fd:read("*l")
			if not lns then break end

			local  ln = lns:match("^#(.+)") or ""
			if ln and ln ~= "" then
				mask = ln
			else
				macaddr, ipaddr = lns:match("(%S+) (%S+)")
					table.insert(data, {
						["mask"] = mask or "",
						["ipaddr"] = ipaddr,
						["macaddr"] = macaddr
					})
				mask = ""
			end
		end

		fd:close()
	end

	return data
end