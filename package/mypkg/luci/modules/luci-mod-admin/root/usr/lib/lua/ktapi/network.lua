--kunteng network api
local M = {}
local fs = require "nixio.fs"
local log = require "luci.log"
local dlv = 3
local ethers_path = "/etc/ethers"

local function kt_mac_ip_banding(list)
    if list == nil  or type(list) ~= "table" then
        log.print(dlv,"kt_mac_ip_banding check false")
        return false
    end
    log.print_r(dlv,list)             
    local fs = io.open(ethers_path,"w+")              
    if fs then                                          
        for k,v in pairs(list) do               
            log.print_r(dlv,k)                
            log.print_r(dlv,v)                
            log.print(dlv,fs)                  
            local str = ""                              
            local mac = v.mac                           
            local ip = v.ip
            fs:write(mac.." "..ip..'\n')
            
        end 
        fs:flush()                                      
        fs:close()
        return true
    else
        log.print(dlv,"kt_mac_ip_banding is called")
        return false
    end
end

local function kt_get_mac_ip_banding_list()
    local fs = io.open(ethers_path,"r")
    local tb = {}
    if fs then
        local ln,mac,ip
        while true do
            ln = fs:read("*l")
            if ln == nil then
               break 
            end
            log.print(dlv,ln)
            mask = ln:match("^(#%S+)")
            if mask == nil then
                mac,ip = ln:match("(%S+) (%S+)")
            
                log.print_r(dlv,{mac = mac,ip = ip})
                local elt = {mac = mac,ip = ip} 
                table.insert(tb,elt)
                log.print_r(dlv,tb)
            end
        end
        fs:close()
    else
        log.print(dlv,"is nil value return")
        return nil
    end
    return tb
end
local function kt_get_5g_exist()
    local kt_uci = require "luci.kt_uci_api"
    local cfg5g = kt_uci.get_wifi_iface_cfg_id("5G")
    if cfg5g ~= nil then
        return true
    end
    return false
end

M = {
    mac_ip_banding = kt_mac_ip_banding,
    get_mac_ip_banding_list = kt_get_mac_ip_banding_list,
    get_5g_exist = kt_get_5g_exist,    
}

return M
