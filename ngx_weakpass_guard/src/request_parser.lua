local M = {}

local cjson = require "cjson.safe"

function M.get_credentials()
    ngx.req.read_body()
    local content_type = ngx.req.get_headers()["content-type"]
    local args
    if content_type and content_type:find("application/json") then
        local body = ngx.req.get_body_data()
        args = cjson.decode(body or "") or {}
    else
        args = ngx.req.get_post_args()
    end
    local username = args.username
    local password = args.password
    return username, password
end

return M
