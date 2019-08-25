local M = {}
local defusrname = "root"
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
    elseif checkpasswd(username,pwdold)  then
        if user.setpasswd(username,pwdnew) == 0 then
	    ret = true 
        end
    else
    end
    return ret
end

M = {
        checkpasswd = checkpasswd,
        setpasswd   = setpasswd,
        defusrname = defusrname,
    }
return M 
