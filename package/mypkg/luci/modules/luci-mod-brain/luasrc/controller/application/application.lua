module("luci.controller.application.application", package.seeall)

function index()
	-- 未开放
	entry({"admin", "application", "market"}, alias("admin", "application"))

	local uci  = require "luci.model.uci".cursor()

	--[[
		10: 系统工具
		30: 研发功能
		60: 网络工具
		90: 辅助工具
		100: 其他

		("DHCP静态绑定"), 10)
		("端口映射"), 12)
		("DDNS"), 13)
		("网络诊断"), 14)
		("网络测速"), 16)
		("wifi环境检测"), 18)
		("定时重启"), 20)

		("Apfree_WifiDog"), 30)
		("WiFi负载均衡"), 32)
		("WiFi考勤表"), 34)
		("内网映射"), 36)

		("Shadowsocks"), 60)
		("KCP加速"), 61)
		("广告屏蔽大师"), 62)
		("文件共享"), 63)
		("FTP服务器"), 64)
		("单线多拨"), 65)
		("拨号日志"), 66)
		("ttyd"), 67)
		("wifiminer"), 68)

		("固件升级"), 99)

		("打印机管理"), 100)
	]]

	if (uci:get("network", "lan", "proto") ~= "dhcp") then
		entry({"admin", "application", "pppoeLog"}, template("application/app_pppoe_log"), _("拨号日志"), 66).index = true
		entry({"admin", "application", "macBind"}, template("application/app_mac_bind"), _("DHCP静态绑定"), 10).index = true
		entry({"admin", "application", "portForward"}, template("application/app_port_forward"), _("端口映射"), 12).index = true
	end

	entry({"admin", "application", "netDiagnose"}, template("application/app_net_diagnose"), _("网络诊断"), 14).index = true
	entry({"admin", "application", "speedTest"}, template("application/app_speed_test"), _("网络测速"), 16).index = true
	entry({"admin", "application", "autoReboot"}, template("application/app_auto_reboot"), _("定时重启"), 20).index = true
	entry({"admin", "application", "printer_list"}, template("application/app_printer"), _("打印机管理"), 30).index = true

	entry({"admin", "application", "macBind", "setData"}, call("setEthersInfo"))
	entry({"admin", "application", "autoReboot", "task"}, call("setRebootCron"))
end

function setEthersInfo()
	local json = require "luci.jsonc"
	local reqData = luci.http.formvalue("data")
	local filepath = "/etc/ethers"
	local codeResp = 0

	local j = json.parse(reqData)
	local fd = io.open(filepath, "w")
	if fd then 
		for k,v in pairs(j) do
			if v.mask ~= "" then
				fd:write('#' .. v.mask ..'\n')
			end
			fd:write(v.mac .. " " .. v.ip ..'\n')
		end
		fd:flush()
		fd:close()
	else
		codeResp = 1
	end

	luci.util.exec("/usr/sbin/service-reload dhcp")
	luci.http.prepare_content("application/json")
	luci.http.write_json({ code = codeResp})
end

function setRebootCron()
	local task = luci.http.formvalue("task")

	luci.util.exec("touch /etc/crontabs/root; sed -i -e '/reboot/d' /etc/crontabs/root")

	if task and task ~= "" then
		local command = "touch -d $(date -d@$(($(date +%s)+2*60 )) +%H:%M:%S) /etc/banner && sync && /sbin/reboot -f"
		luci.util.exec(string.format("echo -e '%s %s' >> /etc/crontabs/root", task, command))
	end

	luci.util.exec("/usr/sbin/service-reload crond")
	luci.http.prepare_content("application/json")
	luci.http.write_json({ code = 0})
end