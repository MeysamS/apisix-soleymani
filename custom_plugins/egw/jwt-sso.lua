local io    = require("io")
local yaml  = require("yaml")
local cjson = require("cjson")
local ngx           = ngx

local plugin_name   = "jwt-sso"

local plugin_schema = {
    type = "object"
}

local _M            = {
    version = 1.0,
    priority = 10,
    name = plugin_name,
    schema = plugin_schema
}

local function load_config(err)
    local file = io.open("/opt/apisix/plugins/config.yaml", "r")
    if not file then
        ngx.log(ngx.ERR, "failed to open config file", err)
        return
    end
    local content = file:read("*a")
    ngx.log(ngx.INFO, "Content of config file:", content)
    file:close()
    return yaml.load(content)
end


local function validate_client(token, config)
    local token_data = cjson.decode(ngx.decode_base64(token:match("^.+%.(.+)%..+$")))
    local client_name = token_data.aud

    if not config.SignInKeysOption.Values[client_name] then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.say("Client not recognized")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    else
        return config.SignInKeysOption.Values[client_name]
    end
end

local function validateSignature(token, key)
    local jwt_obj = jwt:verify(key, token)

    if not jwt_obj.verified then
        -- اگر اعتبارسنجی signature ناموفق بود
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.say("Failed to verify token signature")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end
end

function _M.access(conf)
    local auth_header = ngx.var.http_Authorization
    if auth_header then
        local _, _, token = string.find(auth_header, "Bearer%s+(.+)")
        if token then
            local config, err = load_config()
            if not config then
                ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
                ngx.log(ngx.ERR, "Failed to load configuration: ", err)
                ngx.say("Failed to load configuration")
                ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
            end
            ngx.log(ngx.INFO, "token value ---------->: ", cjson.encode(token))
            local key = validate_client(token, config)
            validateSignature(token, key)
        else
            ngx.status = ngx.HTTP_UNAUTHORIZED
            ngx.say("Missing token")
            ngx.exit(ngx.HTTP_UNAUTHORIZED)
        end
    else
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.log(ngx.ERR, "Authorization header not found: ", err)
        ngx.say("Authorization header not found")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end
end

return _M