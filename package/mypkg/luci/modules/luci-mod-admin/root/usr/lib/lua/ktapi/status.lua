-- kunteng network status api

local M = {}
local dlv = 3 -- control debug message output level
local uci = require "luci.model.uci".cursor()
local log = require "luci.log"
local function kt_dhcp_leases()
    local rv = {}
    local nfs = require "nixio.fs"
    local leasefile = "/tmp/dhcp.leases"

    uci:foreach("dhcp","dhsmasq",
	function(s)
            if s.leasefile and nfs.access(s.leasefile) then
                leasefile = s.leasefile
                return false
            end
        end)
    local fd = io.open(leasefile,"r")
    log.print_r(dlv,fd)
    if fd then
        while true do
            local ln = fd:read("*l")
            if ln then
                local ts,mac,ip,name,duid = ln:match("^(%d+) (%S+) (%S+) (%S+) (%S+)")
		    if ts and mac and ip and name and duid then
                        if not ip:match(":") then
                            local sh_fd = io.popen("ktpriv get_mac_source " .. mac) 
                            if sh_fd then
                                src = sh_fd:read("*all")
                                io.close(sh_fd)
                            end
                            src = tonumber(src) 
                            if src == 0 then
                                src = "wired"
                            elseif src == 1 then
                                src = "wireless" 
                            else
                                src = "offline"
                            end
                            
                            rv[#rv+1] = {
                                family  = "ipv4",
                                expires = os.difftime(tonumber(ts) or 0,os.time()),
                                macaddr = mac, 
                                ipaddr  = ip, 
                                hostname = ((name ~= "*") and name or "unknow"),
                                mac_source = src
			    }
                        elseif ip:match(":") then
                            rv[#rv+1] = {
                                family = "ipv6",
                                expires = os.difftime(tonumber(ts) or 0,os.time()),
                                ipaddr = ip,
                                duid   = (duid ~= "*") and duid,
                                hostname = (name ~= "*") and name,
                            }	
                        end
                   end 
            else
                break
            end
        end
    fd:close()
    end
    log.print_r(dlv,rv)
    return rv
end
M = {
 dhcp_leases = kt_dhcp_leases,
}
return M


