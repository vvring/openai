local M = {}
local config = require "ngx_weakpass_guard.src.config"
local ngx_shared = ngx.shared
local dict = ngx_shared.guard_ratelimit or ngx_shared.DICT

function M.inc(ip_user)
    local new_val, err = dict:incr(ip_user, 1, 0, config.config.fail_window)
    if not new_val then
        ngx.log(ngx.ERR, "ratelimit incr error: ", err)
        return 0
    end
    return new_val
end

function M.exceeded(ip_user)
    local count = dict:get(ip_user)
    if not count then return false end
    return count >= config.config.fail_threshold
end

return M
