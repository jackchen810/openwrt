module("luci.controller.advanced.index", package.seeall)

function index()
	--entry({"admin", "advanced"}, template("advanced/adv_dhcp"),nil, 10)
	entry({"admin", "advanced", "dhcp"}, template("advanced/adv_dhcp"), _("DHCP Settings"), 10).index = true
	entry({"admin", "advanced", "mtu"}, template("advanced/adv_mtu"), _("MTU Settings"), 15).index = true
	entry({"admin", "advanced", "passwd"}, template("advanced/adv_passwd"), _("Set Password"), 20).index = true
end
