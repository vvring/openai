local M = {}
local config = require "ngx_weakpass_guard.src.config"

local weak_dict = {}

local function load_dict(path)
    weak_dict = {}
    local f, err = io.open(path, "r")
    if not f then
        ngx.log(ngx.ERR, "failed to open dict: ", err)
        return
    end
    for line in f:lines() do
        weak_dict[line:lower()] = true
    end
    f:close()
end

function M.init()
    load_dict(config.config.weakpass_dict)
end

function M.is_weak(password)
    if not password then return false end
    if weak_dict[password:lower()] then
        return true
    end
    if #password < 8 then
        return true
    end
    return false
end

return M
