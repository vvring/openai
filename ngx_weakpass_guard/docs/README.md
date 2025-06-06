# ngx_weakpass_guard

This is a simple OpenResty-based plugin to guard login endpoints against weak passwords and brute-force attempts.

## Usage

1. Copy the `ngx_weakpass_guard` directory into your Lua path.
2. In your `nginx.conf`, define shared dictionaries and run the guard in your login location:

```nginx
lua_shared_dict guard_blacklist 10m;
lua_shared_dict guard_ratelimit 10m;

init_by_lua_block {
    local guard = require "ngx_weakpass_guard.src.core"
    guard.init("/path/to/weakpass.conf")
}

server {
    location /login {
        content_by_lua_block {
            local guard = require "ngx_weakpass_guard.src.core"
            guard.run()
            -- your login logic here
        }
    }
}
```

## Configuration

See `conf/weakpass.conf` for available options.
