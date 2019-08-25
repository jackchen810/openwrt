#!/usr/bin/lua

local PPPOE_RESULT = {
	['PEER_NO_RESP'] =  {
		p = {
			"Timeout waiting for PADO packets\n$",
			"Unable to complete PPPoE Discovery\n$",
			"Timeout waiting for PADS packets\n$"
		},
		msg = "错误678：无法建立连接,远程计算机没有响应.",
		vcode = 678
	},
	['NO_MORE_SESSION'] = {
		p = {
			"CHAP authentication failed: Max Online Number,ErrorNumber:9\n$"
		},
		msg = "错误691：身份认证失败：已超过最高在线数.",
		vcode = 691
	},	
	['MODEM_HANGUP'] = {
		p = {
			"Modem hangup\n$",
		},
		msg = "错误619：不能建立连接,Modem已挂断.",
		vcode = 619
	},
	['AUTH_FAILD'] = {
		p = {
			"CHAP authentication failed\n$",
			"PAP authentication failed\n$"
		},
		msg = "错误691：连接失败,用户名或密码不正确.",
		vcode = 691
	}
}

local PPPOE_CONFIG = { 
	logfile = "/tmp/ppp.log",
	check_interval = 2
}

local function popLastMsg(str)
	local rest = str
	local last, prev

	return function ()
		prev = rest
		if not rest then return rest end		 
		rest, last = rest:match('(.+\n)(.+\n)$')
		if last then return last else return prev end
	end
end

local function matchPattern(line)
	for key, patterns in pairs(PPPOE_RESULT) do
		for i, p in ipairs(patterns.p) do
			m = line:find(p)
			if m then return patterns end
		end
	end
	
	return nil
end

function parsePPPoeLog()
	local fs = require "nixio.fs"
	
	local lines = fs.readfile(PPPOE_CONFIG.logfile)   
	if not lines then return nil end

	for ln in popLastMsg(lines) do
		local r = matchPattern(ln)
		if r then
			return r.msg
		end
	end

	return nil
end

print(parsePPPoeLog())