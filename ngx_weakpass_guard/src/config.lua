local M = {}
M.config = {
    login_path = "/login",
    weakpass_dict = "dict/weak_passwords.txt",
    log_path = "/var/log/ngx_weakpass_guard.log",
    fail_threshold = 10,
    fail_window = 60,
    blacklist_duration = 3600,
    username_whitelist = {},
    username_blacklist = {}
}

function M.load(path)
    local cfg = M.config
    local f, err = io.open(path, "r")
    if not f then
        ngx.log(ngx.ERR, "failed to open config: ", err)
        return cfg
    end
    for line in f:lines() do
        local key, val = line:match("^%s*([%w_]+)%s*=%s*(.+)%s*$")
        if key and val then
            local num = tonumber(val)
            if num then
                cfg[key] = num
            elseif val == "{}" then
                cfg[key] = {}
            else
                cfg[key] = val:gsub('"', '')
            end
        end
    end
    f:close()
    return cfg
end

return M
