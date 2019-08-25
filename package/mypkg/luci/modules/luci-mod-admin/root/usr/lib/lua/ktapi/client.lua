local os, pairs, string, table, tonumber, io ,ipairs= os, pairs, string, table, tonumber, io, ipairs

local status 	= require "luci.tools.status"
local util	= require "luci.util"
local uci  = require "luci.model.uci".cursor()

module "ktapi.client"

function brlantable()
	local data = {}
	local k = { "port no", "mac addr", "is local", "ageing timer" }
	local ps = util.execi("ktpriv get_mac_list")
	
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


function get_current_client_list()
	local line_deviceResp = {}
	local clientlist = {}
	local hostname_hash = {}
	local ipaddr_hash = {}
	local macaddr, ipaddr, hostname, connmode

	line_deviceResp = brlantable()
	
	for _, user in ipairs(status:dhcp_leases()) do
		hostname_hash[user['macaddr']] = ((user["hostname"] == false) and "" or user["hostname"])
		ipaddr_hash[user['macaddr']] = user['ipaddr']
	end

	if line_deviceResp then
		for _, net in ipairs(line_deviceResp) do
		
			if net['is local'] ~= "yes" then
				macaddr = net['mac addr']
				
				if hostname_hash[macaddr] ~= nil and hostname_hash[macaddr] ~= "" then
					hostname = hostname_hash[macaddr]
				else
					hostname = "unknown"
				end			
				
				if ipaddr_hash[macaddr] ~= nil and ipaddr_hash[macaddr] ~= "" then
					ipaddr = ipaddr_hash[macaddr]
				else
					ipaddr = util.exec("ktpriv get_ip_by_mac "..macaddr)
				end
				
				connmode = ((tonumber(util.exec("ktpriv get_mac_source "..macaddr)) == 1) and "wireless" or "wired")

				table.insert(clientlist, {
					['ipaddr'] = ipaddr,
					['macaddr'] = macaddr,
					['mac_source'] = connmode,
					['hostname'] = hostname
				})
			end
		end
	end
	
return clientlist
end

function getClientList()
	return get_current_client_list()
end

function wifi_table()
	local data = {}

	local function get_wireless_list(command, t)
		local cmd = util.execi(command)
			if not cmd then
				return
			else
				cmd()
			end
			
			for line in cmd do
				if mac_type(line) then 
					table.insert(t, {line = true})
				end
			end
		return t
	end
	
	local iface_dir = util.execl("ls /sys/class/net")
	
	for _, n in ipairs(iface_dir) do
	
		if n:match('^ath') == "ath" then
			data = get_wireless_list('wlanconfig %q list sta | cut -d " " -f 1' % n, data)
		elseif 
			n:match('^ra') == "ra" then
			data = get_wireless_list('iwpriv %q get_mac_table | cut -d " " -f 1' % n, data)
		end		
	end
	
	return data
end

function mac_type(val)
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