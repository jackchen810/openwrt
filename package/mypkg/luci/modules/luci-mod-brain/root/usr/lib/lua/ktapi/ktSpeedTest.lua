module ("ktapi.ktSpeedTest", package.seeall)

local util = require "luci.util"
local json = require "ktapi.ktJson"
local fs   = require "nixio.fs"

local QOS_CONFIG_PATH = "/etc/config/apfreeqos"
local QOSCONFIG = "apfreeqos"

local function distance(lat1, lon1, lat2, lon2)
	local radius = 6371  
	local dlat = math.rad(lat2 - lat1)
	local dlon = math.rad(lon2 - lon1)
	local a = (math.sin(dlat / 2) * math.sin(dlat / 2) + math.cos(math.rad(lat1)) * math.cos(math.rad(lat2)) * math.sin(dlon / 2) * math.sin(dlon / 2))
	local c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
	local d = radius * c

	return d
end

local function getConfig()
	local client = {}
	local raw = util.exec("curl http://www.speedtest.net/speedtest-config.php -s -m 10 | grep \"<client\" | awk {'print $3 $4'}")
	local lat, lon = string.match(raw, ("lat=\"(%d+%.%d+)\"lon=\"(%d+%.%d+)\""))

	client["lat"] = lat or "39.9289"
	client["lon"] = lon or "116.3883"

	return client
end

local function closestServers()
	local server = {}
	local closest = {} 
	local location = getConfig()

	for line in util.execi('curl http://c.speedtest.net/speedtest-servers-static.php -s -m 10 | grep \"China\"') do
		local _url, _lat, _lon = string.match(line, 'url=\"(.+)\".*lat=\"(%-*%d+%.%d+)\".*lon=\"(%-*%d+%.%d+)\"')
		if _url and _lat and _lon then
			local _dis = distance(location.lat, location.lon, _lat, _lon)
			server[_url] = {dis = _dis}
		end
	end

	if server then
		for i= 1, 5 do
			local closest_dis = 10000
			local closest_url = nil

		for _url, entry in pairs(server) do
			_dis = tonumber(entry.dis)
			if _dis < closest_dis then
				closest_url = _url
				closest_dis = _dis
			end
		end

		if closest_url then 
			table.insert(closest, closest_url)
			server[closest_url] = nil 
			end
		end
	end

	return closest 
end

local function downloadTime(url)
	local time_download = nil
	local raw = util.exec(string.format("curl -o /dev/null %s -w \"\%%{time_total}\" -s --connect-timeout 1 -m 2", url))

	if raw then
		time_download = string.match(raw, '(%d+%.%d+)')
	end

	return time_download
end

local function getBestServer(servers)
	local best = nil
	local minLatency=10
 
	for i, server in pairs(servers) do
		url = string.format("%s/latency.txt", server)
		latency=downloadTime(url) 
		if latency then 
			latency = tonumber(latency)
			if latency < minLatency then
				minLatency = latency
				best = server
			end
		end
	end

--[[ 
	if best then
		print("find best server " .. best)
	end
]]
	return best
end

local function downloadSpeed(urls)   
	local time_download, size_download, time_download_total, size_download_total
	time_download_total = 0
	size_download_total = 0

	for i, url in pairs(urls) do
		local raw = util.exec(string.format("curl -o /tmp/speedtest.tmp %s -w \"%%{size_download} \%%{time_total}\" -s -m 15", url))
		if raw then
			size_download, time_download = string.match(raw, '(%d+)%s(%d+%.%d+)')
			if size_download and time_download then
				time_download_total = time_download_total + time_download
				size_download_total = size_download_total + size_download 
			end
		end
	end

	if time_download_total ~= 0 then
		return size_download_total / (1024 * time_download_total)
	else
		return 0
	end 
end

local function uploadSpeed(url)
	local time_upload, size_upload, time_upload_total, size_upload_total
	time_upload_total = 0
	size_upload_total = 0
	local filename = "/tmp/speedtest.tmp"
	local raw = util.exec(string.format("curl -F \"file=@%s\" %s -w \"%%{size_upload} \%%{time_total}\" -s -o /dev/null -m 15", filename, url));

	if raw then
		size_upload, time_upload = string.match(raw, '(%d+)%s(%d+%.%d+)')
		if size_upload and time_upload then
			time_upload_total = time_upload_total + time_upload
			size_upload_total = size_upload_total + size_upload 
		end
	end

	if time_upload_total ~= 0 then
		return size_upload_total / (1024 * time_upload_total)
	else
		return 0
	end 
end

function speedTest()
	local speedTest = {download = 0, upload = 0}
	local uci  = require "luci.model.uci".cursor()

	local closest = closestServers()
	if closest then 
		local best = getBestServer(closest)
		if best then 
			local urls = {}
			local sizes = {350, 500, 750, 1000, 1500, 2000, 2500, 3000, 3500, 4000}
			local sizes = {4000}

			for k, size in pairs(sizes) do
				for i=1, 1 do
					local url = string.gsub(best, "upload.%a+", string.format("random%sx%s.jpg", size, size))
					table.insert(urls, url)
				end
			end

			if urls then
				local downSpeed = downloadSpeed(urls)
				 speedTest.download = math.modf(downSpeed * 100) / 100

				local upSpeed = uploadSpeed(best)
				speedTest.upload = math.modf(upSpeed * 100) / 100
			end
		end
	end

--[[	local _dump = assert(io.open(SPEEDTEST_DATA_PATH, "w"))
		local _json = json.Encode(speedTest)

		_dump:write(_json)
		_dump:flush()
		_dump:close()
		 ]]

	if fs.access("/tmp/speedtest.tmp", "f") then
		util.exec("rm /tmp/speedtest.tmp")
	end

	util.exec("touch ".. QOS_CONFIG_PATH)

	uci:section(QOSCONFIG, "other_rule", "bandwidth", nil)

	uci:set(QOSCONFIG, "bandwidth", "download", speedTest.download)
	uci:set(QOSCONFIG, "bandwidth", "upload", speedTest.upload)
	uci:commit(QOSCONFIG)

	return speedTest
end