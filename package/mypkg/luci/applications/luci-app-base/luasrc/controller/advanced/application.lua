module("luci.controller.advanced.application", package.seeall)

function index()
	entry({"admin", "advanced", "application"}, template("advanced/adv_app"), _("扩展应用"), 99).index = true
end
