local M = {}
local config = require "ngx_weakpass_guard.src.config"
local ngx_shared = ngx.shared
local dict = ngx_shared.guard_blacklist or ngx_shared.DICT

local function dict_set(ip, ttl)
    dict:set(ip, true, ttl)
end

function M.add(ip)
    dict_set(ip, config.config.blacklist_duration)
end

function M.is_blocked(ip)
    return dict:get(ip) ~= nil
end

return M
