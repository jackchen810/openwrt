module("luci.controller.application.app_timesheet", package.seeall)

function index()
		entry({"admin", "application", "timesheet"}, template("application/app_timesheet"), _("WiFi考勤表"), 34).index = true
		entry({"admin", "application", "timesheet", "getContacts"}, call("getContacts"))
		entry({"admin", "application", "timesheet", "getAttendance"}, call("getAttendance"))
		entry({"admin", "application", "timesheet", "delAttendance"}, call("delAttendance"))
		entry({"admin", "application", "timesheet", "addAttendance"}, call("addAttendance"))
		entry({"admin", "application", "timesheet", "setMailService"}, call("setMailService"))
		entry({"admin", "application", "timesheet", "setAttendanceTime"}, call("setAttendanceTime"))
end

local uci = require "luci.model.uci".cursor()

DBNAME = "/etc/attendence.sdb"
TABLES = {
	['CONTACTS'] = "employee_tbl",
	['ATTENDANCE'] = "timesheet_tbl"
}

function closedb(dbenv,dbcon)
	dbcon:close()
	dbenv:close()
end

function opendb()
	local luasql = require "luasql.sqlite3"
	local dbenv = assert(luasql.sqlite3())

	dbcon = assert(dbenv:connect(DBNAME))

	return dbenv,dbcon
end

function rows(dbcon, sql)
	local d = {}
	local c = assert(dbcon:execute(sql))
	local r = c:fetch ({}, "a")

	while r do
		table.insert(d, r)
		r = {}
		r = c:fetch (r, "a")
	end

	c:close()

	return d
end

function query(sql)
	local arryOutput = {}

	local dbenv, dbcon = opendb()

	arryOutput = rows(dbcon, sql)

	closedb(dbenv, dbcon)

	luci.http.prepare_content("application/json")
	luci.http.write_json(arryOutput, true)
end

function exesql(sql)
	local dbenv, dbcon = opendb()
	local r = assert(dbcon:execute(sql))

	closedb(dbenv, dbcon)

	luci.http.prepare_content("application/json")
	luci.http.write_json(r, true)
end

function getContacts()
	local name = luci.http.formvalue("name")
	local sql = string.format("SELECT * from %s", TABLES['CONTACTS'])

	if name and name ~= "" then
		sql = string.format("%s WHERE name = '%s'", sql, name)
	end

	return query(string.format([[%s]], sql))
end

function getAttendance()
	local json = require "luci.jsonc"

	local formValue = luci.http.formvalue("reqdata")
	local reqData = json.parse(formValue)

	local queryDate = reqData.date
	local name = reqData.name
	local datePicker = reqData.datePicker
	local datePicker2 = reqData.datePicker2

	local function getMonday()
		for i = 0, 6 do
			if os.date('%A', os.time()-24*3600*i) == "Monday" then
				return(os.date("%Y-%m-%d",os.time()-3600*24*i))
			end
		end
	end

	if queryDate == "today" then
		queryDate = os.date("%Y-%m-%d")
	elseif queryDate == "yesterday" then
		queryDate = os.date("%Y-%m-%d",os.time()-3600*24)
	elseif queryDate == "week" then
		datePicker = getMonday()
		queryDate = nil
	elseif queryDate == "month" then
		datePicker = os.date("%Y-%m-01")
		queryDate = nil
	elseif queryDate == "lastmonth" then
		datePicker = os.date("%Y-%m-01", os.time()-3600*24*31)
		datePicker2 = os.date("%Y-%m-%d", os.time()-3600*24*(tonumber(os.date("%d"))))
		queryDate = nil
	end

	local sql = string.format("SELECT * from %s", TABLES['ATTENDANCE'])

	if queryDate and queryDate ~= "" then
		sql = string.format("%s WHERE date = '%s'", sql, queryDate)
	elseif datePicker then
		if datePicker2 == "" then datePicker2 = os.date("%Y-%m-%d") end
		sql = string.format("%s WHERE date BETWEEN '%s' AND '%s'", sql, datePicker, datePicker2)
	end

	if name ~= "" then
		sql = string.format("%s AND name = '%s'", sql, name)
	end
	
	return query(string.format([[%s]], sql))
end

function delAttendance()
	local id = luci.http.formvalue("id")
	local sql = string.format([[DELETE from %s WHERE id = '%d']], TABLES['CONTACTS'], tonumber(id))

	return exesql(sql)
end

function addAttendance()
	local name = luci.http.formvalue("name")
	local mac = luci.http.formvalue("mac")
	local email = luci.http.formvalue("email")

	local sql = string.format([[INSERT INTO %s (mac, name, email) VALUES('%s', '%s', '%s')]], TABLES['CONTACTS'], mac:upper(), name, email)

	return exesql(sql)
end

function setMailService()
	local fs  = require "nixio.fs"
	local e_mail = luci.http.formvalue("email")
	local password = luci.http.formvalue("passwd")
	local server = luci.http.formvalue("server")
	local port = luci.http.formvalue("port")
	local period = luci.http.formvalue("period")

	-- 生成配置文件
	local conf = string.format(
					"account Administrator\n" ..
					"host %s\n" ..
					"port %s\n" ..
					"auth login\n" ..
					"tls off\n" ..
					"from %s\n" ..
					"user %s\n" ..
					"password %s\n" ..
					"logfile /var/log/msmtp.log\n" ..
					"account default : Administrator\n"
					, server, port, e_mail, e_mail, password)

	fs.writefile("/etc/msmtprc", conf)

	-- 设置定时任务
	luci.util.exec("touch /etc/crontabs/root; sed -i -e '/sendmail/d' /etc/crontabs/root")
	local command = "0 1 * * * /usr/bin/sendmail.sh " .. period
	luci.util.exec(string.format("echo -e '%s' >> /etc/crontabs/root", command))
	luci.util.exec("/usr/sbin/service-reload crond")

	luci.http.prepare_content("application/json")
	luci.http.write_json({ code = 0 })
end

function setAttendanceTime()
	local aTime = luci.http.formvalue("aTime")
	local lTime = luci.http.formvalue("lTime")

	uci:set("attendence", "time", "arrival_time", aTime)
	uci:set("attendence", "time", "leave_time", lTime)
	uci:commit("attendence")

	luci.http.prepare_content("application/json")
	luci.http.write_json({ code = 0 })
end
