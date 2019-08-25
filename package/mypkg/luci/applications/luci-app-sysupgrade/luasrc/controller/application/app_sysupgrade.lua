module("luci.controller.application.app_sysupgrade", package.seeall)

function index()
	entry({"admin", "application", "upgrade"}, template("application/app_upgrade"), _("固件升级"), 99).index = true
	entry({"admin", "application", "upgrade", "doUpgrade"}, call("upload_bin"))
end

local IMAGE_PATH = "/tmp/web_firmware.bin"
local ktUtil = require "ktapi.ktUtil"

function upload_bin()
	local h = require "luci.http"
	local io = require "nixio"
	local flag = true
	local run = true
	local fd

	local function image_supported()
		-- 检查镜像
		return ( 0 == os.execute(
			". /lib/functions.sh; " ..
			"include /lib/upgrade; " ..
			"platform_check_image " .. IMAGE_PATH .. " &>/dev/null"
		) )
	end

	local function boadr_supported()
		-- 检查镜像
		return ( 0 == os.execute(
			". /lib/functions.sh; " ..
			"include /lib/upgrade; " ..
			"board_check_image " .. IMAGE_PATH .. " &>/dev/null"
		) )
	end

	h.setfilehandler(
		function(filed, chunk, eof)
			if not filed or not run then
				return
			end

			if flag then
				flag = false
			end

			if not fd then
				fd = io.open(IMAGE_PATH, "w")
			end

			fd:write(chunk)

			if eof and fd then
				fd:close()
				fd = nil
				if image_supported() and boadr_supported() then
					h.write("<script>parent.rspMessage(2)</script>")
					local keep = (luci.http.formvalue("saveconf") == "1") and "" or "-n"
					ktUtil.fork_exec("sleep 2; killall dropbear uhttpd; sleep 1; /sbin/sysupgrade -v %s %q" %{ keep, IMAGE_PATH })
				else
					h.write("<script>parent.rspMessage(1)</script>")
				end
			end
		end
	)

	if h.formvalue("act") == "upload" then
		return
	end

end