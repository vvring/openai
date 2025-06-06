local config = require "ngx_weakpass_guard.src.config"
local weakpass = require "ngx_weakpass_guard.src.weakpass_check"
local ratelimit = require "ngx_weakpass_guard.src.ratelimit"
local blacklist = require "ngx_weakpass_guard.src.blacklist"
local parser = require "ngx_weakpass_guard.src.request_parser"
local logger = require "ngx_weakpass_guard.src.logger"

local M = {}

function M.init(config_path)
    config.load(config_path)
    weakpass.init()
end

function M.run()
    local cfg = config.config
    if blacklist.is_blocked(ngx.var.remote_addr) then
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    if ngx.var.uri ~= cfg.login_path then
        return
    end

    local username, password = parser.get_credentials()
    if not username or not password then
        return
    end

    if cfg.username_blacklist[username] then
        blacklist.add(ngx.var.remote_addr)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    if not cfg.username_whitelist[username] then
        if weakpass.is_weak(password) then
            local ip_user = ngx.var.remote_addr .. ":" .. username
            local count = ratelimit.inc(ip_user)
            if ratelimit.exceeded(ip_user) then
                blacklist.add(ngx.var.remote_addr)
                return ngx.exit(ngx.HTTP_FORBIDDEN)
            end
        end
    end

    local log_line = table.concat({ngx.var.remote_addr, username, password, ngx.var.http_user_agent or "-", ngx.time()}, " ")
    logger.log(log_line)
end

return M
