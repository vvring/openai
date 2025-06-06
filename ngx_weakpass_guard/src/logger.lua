local M = {}
local config = require "ngx_weakpass_guard.src.config"
local io_open = io.open

local function open_log()
    local f, err = io_open(config.config.log_path, "a")
    if not f then
        ngx.log(ngx.ERR, "open log fail: ", err)
        return nil
    end
    return f
end

function M.log(info)
    local f = open_log()
    if not f then return end
    f:write(info .. "\n")
    f:close()
end

return M
