--kunteng lua script api 
local M = {}
local defusrname = "root"
local log = require "luci.log"
local dlv = 3
local function checkpasswd(username,pwd)
    local user = require "luci.sys".user
    local ret  = user.checkpasswd(username, pwd)
    return ret
end

local function setpasswd(username,pwdold,pwdnew)
    local user = require "luci.sys".user
    local ret  = false
    if username == nil then
	log.print(dlv,"setpasswd error because of username is nill")
    elseif checkpasswd(username,pwdold)  then
        log.print(dlv,username  ..  pwdnew)
        if user.setpasswd(username,pwdnew) == 0 then
	    ret = true 
        end
    else
        log.print(dlv,"setpasswd error becase of passwd is mismatch")
    end
	log.print(dlv,ret)
    return ret
end

M = {
        checkpasswd = checkpasswd,
        setpasswd   = setpasswd,
        defusrname = defusrname,
    }
return M 
