#!/usr/bin/lua

function getidbyband(tband)
	local ret=""
	local uci=require("luci.model.uci")
	local _uci=uci.cursor()
   	_uci:foreach("wireless","wifi-device",function(s)
    	local lcName = s[".name"]
    	--print("lcName = "..lcName)
     	local lcband = _uci:get("wireless",lcName,"band")
     	if(lcband==tband) then 
     		ret=lcName
     	end
   	end
   )
   return ret
end

function writefile( str )
  local file = io.open("/tmp/test.txt","a")
  file:write(str)
  if file then file:close() end
end
function getbandid(arg)
	local ret="2.4G"
	if(arg=="2") then
		ret="2.4G"
	elseif arg == "5" then
		ret="5G"
	end
	return ret;
end

function checkch(band,sch)
  local ch = tonumber(sch);
  local chh=0;
  if band=="2" then
    if ch>0 and ch<14 then
      return ch
    else
      return chh
    end
  end
  if band=="5" then
    if ch==149 then
      return ch
    elseif ch==153 then
      return ch
    elseif ch==157 then
      return ch
    elseif ch==161 then
      return ch
    elseif ch==165 then
      return ch
    else
      return 153
    end
  end
end

function get_iface_id( device_name )
	local ret = -1
	local uci=require("luci.model.uci")
	local _uci = uci.cursor()

	local i = 0

	_uci:foreach("wireless", "wifi-iface", function(s)
		local lif_name = s[".name"]
		local ldev_name = _uci:get("wireless",lif_name,"device")

		-- print("ldev_name = ", ldev_name, "device_name=", device_name, "i=", i)
		if (ldev_name == device_name) then
			-- print("result i = ", i)
			ret = i
			return
		end

		i = i + 1

	end
	)
	return ret

end

if(arg[1] == "chan") then
	if(arg[2]=="get") then
		--writefile("get"..arg[3]) 
		local bid=getbandid(arg[3])
		local uci=require("luci.model.uci")
		local _uci=uci.cursor()
		local cfg=getidbyband(bid)
		local ch = _uci:get("wireless",cfg,"channel")
		if ch == nil then 
			ch="unkown" 
		end
		if ch== "auto" then
			ch=0
		end
		print(ch)

	elseif arg[2] == "set" then
		--writefile("set"..arg[3]) 
		local bid=getbandid(arg[3])
		local uci=require("luci.model.uci")
		local _uci=uci.cursor()
		local cfg=getidbyband(bid)
		local ch=checkch(arg[3],arg[4])

		test3=_uci:set("wireless",cfg,"channel",ch)
		_uci:commit("wireless")
  	end

elseif(arg[1] == "iface") then
	local tband = getbandid(arg[2]) --only supprt arg "2" and "5"
	local ret=""
	local uci=require("luci.model.uci")
	local _uci=uci.cursor()
	_uci:foreach("wireless","wifi-device",function(s)
		local lcName = s[".name"]
		--print("lcName = "..lcName)
		local lcband = _uci:get("wireless",lcName,"band")

		if(lcband==tband) then 
			ret=lcName
			return
		end
	end
	)

	if (ret ~= "") then
		local iface_no = get_iface_id(ret)
		-- print("local name = ", ret)
		-- print("iface no = ", iface_no)
		if (iface_no ~= -1) then
			print(iface_no)
		end
	end

end


