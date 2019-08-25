--this module is for kunteng fit for different platform uci option

local M = {}

local _uci = require("luci.model.uci").cursor()

local function get_uci_config_id(config,section_type,option,option_value)
	local ret = nil
	
    check = ((config == nil) or (config =="")) or ((section_type == nil) or (section_type =="")) or ((option_value == nil) or (option_value =="")) or ((option == nil) or (option ==""))
	
	if not check then                                                                                                                                                                       
		_uci:foreach(config,section_type,function(s)                                                                          
					local s_name = s[".name"]
					local value = _uci:get(config,s_name,option)
					
					if section == "wifi-iface" then
						if _uci:get(config,s_name,"mode") ~= "ap" then
							return
						end
					end 
					
					if value == option_value then
						ret = s_name
					end
					
				end 
			)
	end
	
	return ret
end

function M.get_wifi_device_cfg_id(band)
    if band == "2G" or band == "5G" then
		option = _uci:get("luci_platform","wireless","device_option_" .. band)
		value = _uci:get("luci_platform","wireless","device_option_value_" .. band)

		if option and value then
			return get_uci_config_id("wireless","wifi-device",option,value) 
		end        
    end
	
	return nil    
end

function M.get_wifi_iface_cfg_id(band)
    if band == "2G" or band == "5G" then
		option = _uci:get("luci_platform","wireless","iface_option_" .. band)
		value = _uci:get("luci_platform","wireless","iface_option_value_" .. band)
		
		if option and value then
			return  get_uci_config_id("wireless","wifi-iface",option,value)
		end
    end

	return nil    
end

return M

