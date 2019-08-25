-- Ckpyright 2008 Steven Barth <steven@midlink.org>
-- Copyright 2008-2011 Jo-Philipp Wich <jow@openwrt.org>
-- Licensed to the public under the Apache License 2.0.

module("luci.controller.admin.system", package.seeall)



function index()

    --entry({"admin", "system", "reboot"}, template("admin_system/reboot"), _("Reboot"), 90)
    entry({"admin", "system", "reboot"}, post("action_reboot"))
    entry({"admin", "system", "set_system_clock"}, post("set_system_clock"))
    entry({"admin", "system", "set_wizard"}, post("set_wizard"))
	entry({"admin", "system", "skip_wizard"}, call("remove_fistlogin"))
    entry({"admin", "system", "sys_passwd_set"}, post("sys_passwd_set"))
	
    entry({"admin", "system", "dhcp_set"}, post("dhcp_set"))
    entry({"admin", "system", "mac_ip_banding"}, post("mac_ip_banding"))	
    entry({"admin", "system", "language"}, post("change_language")) 

end

---------------------------------------------------------------------------------------
--	全局函数 变量
--------------------------------------------------------------------------------------- 

--首次登陆标识
local FIRSTLOGINPATH = "/usr/lib/lua/luci/firstlogin"
local uci  = require "luci.model.uci".cursor()		

function set_system_clock()
    local set = tonumber(luci.http.formvalue("set"))
	
    if set ~= nil and set > 0 then
        local date = os.date("*t",set )
	if date then
            luci.sys.call("date -s '%04d-%02d-%02d %02d:%02d:%02d'" %{
            date.year, date.month, date.day, date.hour, date.min, date.sec
		})
        end
    end
	
    local ntp = luci.http.formvalue("ntp")
	
    if ntp == "1" then
        service_action('sysntpd','enable')
    else
        service_action('sysntpd','disable')
    end
	
    luci.http.prepare_content("application/json")
    luci.http.write_json({result = true})
end

function remove_fistlogin()
	local fs = require "nixio.fs"
	if fs.access(FIRSTLOGINPATH) then
		fs.remove(FIRSTLOGINPATH)
	end	
	 luci.http.write_json({ result = true })
end


function set_wizard()
 	local kt_uci = require "luci.kt_uci_api"
 	local jsn = require "luci.jsonc"
	local nw = require "luci.controller.admin.network"
 
 	local wan_set = luci.http.formvalue("wizard_set")
 	local be_set = false
 	local set = jsn.parse(wan_set)
 
 	local cfg2g = kt_uci.get_wifi_iface_cfg_id("2G")
 	local cfg5g = kt_uci.get_wifi_iface_cfg_id("5G")
 	local uci_result = true
 
 	local fs = require "nixio.fs"
 	if fs.access(FIRSTLOGINPATH) then
 		fs.remove(FIRSTLOGINPATH)
 	end	
 
 	if(set.proto == "pppoe") then
 	
 		if set.username == "" and set.password == "" then
 			uci_result = false
 		else
 			nw.clean_wan_set("pppoe")
 			uci:set("network","wan","username",set.username)
 			uci:set("network","wan","password",set.password)
 
 			be_set = true       -- wifi to be set if this flag is true
 		end
 		
 	elseif (set.proto == "dhcp") then
 	
 		nw.clean_wan_set("dhcp")
 		be_set = true
 
 	elseif (set.proto == "static") then
 		if set.ipaddr == "" or set.netmask == "" or set.gateway == "" or set.main_dns == "" then
 			uci_result = false
 		else
 			nw.clean_wan_set("static")
 			uci:set("network","wan","ipaddr",set.ipaddr)
 			uci:set("network","wan","netmask",set.netmask)
 			uci:set("network","wan","gateway",set.gateway)
 			be_set = true
 		end
 	end 
 
	--设置dns, 20160617 zhangzf                                                                   
	if set.backup_dns ~= "" then                                                                    
			uci:set_list("network", "wan", "dns", {set.main_dns, set.backup_dns})                  
	else                                                                                            
			uci:set("network", "wan", "dns", set.main_dns)                                                    
	end
	
	uci:commit("network")                                                                 
	
	if be_set and uci_result ~= false then                                         
		if set.ssid ~= "" then                                                    
				uci:set("wireless",cfg2g,"ssid",set.ssid)                        
				if cfg5g then                                                                   
				uci:set("wireless",cfg5g,"ssid",set.ssid)                                      
				end                                                                             
				uci:commit("wireless")                                                         
		else                                                                      
				uci_result = false                                                
		end                                                               
	end                                                                               
	
	luci.http.prepare_content("application/json")                                                              
	luci.http.write_json({ result = uci_result })                                                                                
	
	fork_exec("sleep 1;/sbin/luci-reload network;/etc/init.d/dnsmasq restart;ifup wan;/etc/init.d/wifidog stop;/etc/init.d/wifidog start")
end 


--service_action 
--input:service-->service name.action:stop, start,restart,enable,disable....
--return:ture-->success,false-->failed.
function service_action(service,action)           
    local sys = require "luci.sys"
    local ret
	
    if action == "enable" then                
       sys.init.enable(service)          
       ret = sys.init.start(service)       
    elseif action == "disable" then               
       sys.init.disable(service)
       ret =  sys.init.stop(service)                
    end 
	
    return ret                                       
end

function action_reboot()
	luci.sys.reboot()
end

function sys_passwd_set()
    local passwd = luci.http.formvalue("sys_passwd")
    local sys    = require "luci.sys"
    local ret    = sys.user.setpasswd("root",passwd)
	
    if ret == 0 then
        ret = true
    else
        ret = false
    end 
	
    luci.http.prepare_content("application/json")
    luci.http.write_json({ result = ret })
end

function dhcp_set()
    local nw = require "ktapi.network"
    local setting = luci.http.formvalue("dhcp_setting")
	
    if setting then
        local jsn = require "luci.jsonc"
        local js_setting = jsn.parse(setting)
		
        uci:set("dhcp","lan","start",js_setting.start)
        uci:set("dhcp","lan","limit",js_setting.limit)
        uci:set("dhcp","lan","leasetime",js_setting.leasetime)
        uci:commit("dhcp")
		
        nw.mac_ip_banding(js_setting.ip_mac_banding_list) 
        ret = true
    else 
        ret = false
    end
	
    luci.http.prepare_content("application/json")
    luci.http.write_json({ result = ret })
--    luci.sys.call("/sbin/luci-reload network wifidog rsyslog")
    fork_exec("sleep 1;/sbin/luci-reload network;/etc/init.d/dnsmasq restart;ifup wan;sleep 1;/etc/init.d/wifidog stop;/etc/init.d/wifidog start")

--    fork_exec("sleep 1;/sbin/luci-reload network;")
end

function change_language()
	local lang = luci.http.formvalue("lang")
	uci:set("luci", "main", "lang", lang)
	uci:commit("luci")
	luci.http.write_json({ result = true })
end

function mac_ip_banding()
    local list = luci.http.formvalue("mac_ip_list")
    if list then                                                    
        local jsn = require "luci.jsonc"                               
        local ip_mac_table = jsn.parse(list)
        local nw = require "ktapi.network"
		
        nw.kt_mac_ip_banding(ip_mac_table)
		
        local fs = io.open("/tmp/ethers","w+")
        fs:write("")
        fs:flush()
        fs:close()
        local fs = io.open("/tmp/ethers","a+")
		
        if fs then
            for k,v in pairs(ip_mac_table) do 
                local str = ""                           
                local mac = v.mac                               
                local ip = v.ip                                 
                if fs then                                      
                    fs:write(mac.." "..ip..'\n')                
                end  
            end 
            fs:flush()
            fs:close()
        end 
		
    end 
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
