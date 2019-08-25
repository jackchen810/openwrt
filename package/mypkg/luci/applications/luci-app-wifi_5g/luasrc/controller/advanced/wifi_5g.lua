module("luci.controller.advanced.wifi_5g", package.seeall)

function index()
	entry({"admin", "advanced", "wifi_5g"}, template("advanced/adv_wifi_5g"), _("5.8G配置"), 99).index = true
end
