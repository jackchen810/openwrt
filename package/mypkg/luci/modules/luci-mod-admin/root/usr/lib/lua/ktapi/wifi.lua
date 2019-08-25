local os, pairs, string, table, tonumber, io ,ipairs= os, pairs, string, table, tonumber, io, ipairs
local status	= require "luci.tools.status"
local network	= require "luci.model.network"
local sys	= require "luci.sys"
local util	 = require "luci.util"
local uci	= require "luci.model.uci".cursor()

module "ktapi.wifi"

function getWifiDevsInfo()
	local ntm = network.init()
	local rv = { }
	
	local dev
	for _, dev in ipairs(ntm:get_wifidevs()) do
		
		local net
		for _, net in ipairs(dev:get_wifinets()) do
			if net:get("mode") == "ap" then			
				table.insert(rv, {
					['device']		= dev:name(),
					['channel'] 	= dev:get("channel"),
					['txpower'] 	= dev:get("txpower"),
					['ssid'] 		= net:get("ssid"),
					['is_up'] 		= net:get("disabled"),
					['encry']		= net:get("encryption"),
					['key'] 		= net:get("key"),
					['hidden'] 		= net:get("hidden"),
				})
		end		
	end
	
	return rv
end

function get_wifi_net(band)
	local ntm = network.init()
	local rv = { }
	
	local dev
	for _, dev in ipairs(ntm:get_wifidevs()) do		
		
		local net
		for _, net in ipairs(dev:get_wifinets()) do		
			if dev:get("band") ~= band then break end
			
			if net:get("mode") == "ap" then			
				table.insert(rv, {
					['device']		= dev:name(),
					['channel'] 	= dev:get("channel"),
					['txpower'] 	= dev:get("txpower"),
					['ssid'] 		= net:get("ssid"),
					['is_up'] 		= net:get("disabled"),
					['encry']		= net:get("encryption"),
					['key'] 		= net:get("key"),
					['hidden'] 		= net:get("hidden"),
				})
			end
		end
	end
	
	return rv
end



function turn_wifi_on()

  local current_status = get_wifi_device()
  if current_status['is_on'] == 1 then
    return
  end

    local netmd = network.init()
    local net = netmd:get_wifinet(DEVICE_ID)
    local dev
    if net~=nil then 
        dev = net:get_device()
    end
    if dev and net then
        dev:set("disabled", nil)
        net:set("disabled", nil)
        netmd:commit("wireless")
        os.execute("env -i /sbin/wifi >/dev/null 2>/dev/null")
    end
end

function turn_wifi_off()
  local current_status = get_wifi_device()
  if current_status['is_on'] == 0 then
    return 
  end

    local netmd = network.init()
    local net = netmd:get_wifinet(DEVICE_ID)
    local dev

    if net~=nil then 
        dev = net:get_device()
    end

    if dev and net then
        os.execute("env -i /sbin/wifi down >/dev/null 2>/dev/null")
        dev:set("disabled", nil)
        net:set("disabled", 1)
        netmd:commit("wireless")
    end
end