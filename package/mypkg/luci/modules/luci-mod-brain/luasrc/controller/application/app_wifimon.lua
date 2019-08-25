module("luci.controller.application.app_wifimon", package.seeall)

function index()
		entry({"admin", "application", "wifimon"}, template("application/app_wifimon"), _("wifi环境检测"), 18).index = true
		entry({"admin", "application", "wifimon", "scanWirelessEnv"}, call("scanWirelessEnv"))
end

function scanWirelessEnv()
	local ktWifi = require "ktapi.ktWifi"

	local codeResp = 1
	local arryOutput = {}

	local apList = ktWifi.platform_scan_ap_list()

	local channelArry = {}

	local i, v
	for i = 1, 11 do
		channelArry[i] = {}
		channelArry[i]['count'] = 0
		channelArry[i]['factor'] = 0
		channelArry[i]['channel'] = i
	end

	if apList then
		codeResp = 0
		arryOutput["apList"] = apList

		for i, v in ipairs(apList) do
			local n = tonumber(v.channel)
			if n <= 11 then
				channelArry[n]["count"] = channelArry[n]["count"] + 1
				channelArry[n]['factor'] = channelArry[n]['factor'] + v.signal + 5

				local near
				for near = -4, 4, 1 do
					if channelArry[n + near] then
						channelArry[n + near]['factor'] = channelArry[n + near]['factor'] + (5 - math.abs(near)) * v.signal
					end
				end
			end
		end
	end

	local function comps(a,b)
		return a.factor < b.factor
	end

	table.sort(channelArry, comps)
	channelArry[1]['factor'] = channelArry[1]['factor'] - 1; -- 避免出现多个最小值, 影响echarts标注

	arryOutput["code"] = codeResp
	arryOutput["chEnv"] = channelArry

	luci.http.prepare_content("application/json")
	luci.http.write_json(arryOutput, true)
end