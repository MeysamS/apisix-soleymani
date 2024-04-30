local io            = require("io")
local ngx           = ngx
local jwt           = require("resty.jwt")
local mysql         = require("resty.mysql")
local cjson         = require("cjson")
local yaml          = require("yaml")
-- local resty_hmac    = require("resty.hmac")
-- local resty_sha256  = require("resty.sha256")
-- local str = require "resty.string"


local plugin_name   = "jwt-uaa"

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

local function validate_token_from_database(token, mssql_options)
    local db, err = mysql:new()
    if not db then
        ngx.log(ngx.ERR, "Failed to instantiate MySQL: ", err)
        return nil, "Failed to instantiate MySQL"
    end

    db:set_timeout(1000) -- 1 second timeout

    local ok, err, errcode, sqlstate = db:connect {
        host = mssql_options.host,
        port = mssql_options.port,
        database = mssql_options.database,
        user = mssql_options.user,
        password = mssql_options.password,
        max_packet_size = 1024 * 1024
    }

    if not ok then
        ngx.log(ngx.ERR, "Failed to connect to MySQL: ", err, ": ", errcode, " ", sqlstate)
        return nil, "Failed to connect to MySQL"
    end

    local token_hash = ngx.md5(token)
    local sql = "SELECT COUNT(*) as count FROM UserToken WHERE token = " .. ngx.quote_sql_str(token_hash)
    local res, err, errcode, sqlstate = db:query(sql)
    if not res then
        ngx.log(ngx.ERR, "Bad result: ", err, ": ", errcode, ": ", sqlstate)
        return nil, "Bad result from MySQL query"
    end

    local count = res[1].count

    local ok, err = db:set_keepalive(10000, 100)
    if not ok then
        ngx.log(ngx.ERR, "Failed to set keepalive: ", err)
    end

    return count > 0
end

-- local function validate_signature_key(jwt_token, key)
--     local hmac = resty_hmac:new(key, resty_hmac.ALGOS.SHA256)
--     local data = jwt_token.payload
--     local signature = jwt_token.signature
--     -- ngx.say("token value ----------> : " .. cjson.encode(jwt_token))
--     -- ngx.say("token value ----------> : " .. jwt_token)
--     -- Re-calculate the signature
--     local calculated_signature = str.to_hex(hmac:final(data))

--     -- Compare the calculated signature with the provided one
--     if calculated_signature == signature then
--         return true
--     else
--         return false
--     end
-- end

local function validate_expire(jwt_token)
    local current_time = ngx.now()
    if jwt_token.payload.exp and jwt_token.payload.exp < current_time then
        return false
    else
        return true
    end
end

local function validate_token(token, bearer_tokens_option, mssql_options)
    local jwt_token, err = jwt:verify(bearer_tokens_option.Key, token)
    if not jwt_token then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.log(ngx.ERR, "Invalid token: ", err)
        ngx.say("Invalid token")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    -- if not validate_signature_key(jwt_token, bearer_tokens_option.Key) then
    --     ngx.status = ngx.HTTP_UNAUTHORIZED
    --     ngx.log(ngx.ERR, "validate_signature : Invalid token - Key:", tostring(jwt_token.key), ", Error: ", err)
    --     ngx.say("Invalid token")
    --     ngx.exit(ngx.HTTP_UNAUTHORIZED)
    -- end

    if not validate_expire(jwt_token) then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.log(ngx.ERR, "Token has expired: ", err)

        ngx.say("Token has expired")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    if not validate_token_from_database(token, mssql_options) then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.log(ngx.ERR, "Token not found in database: ", err)
        ngx.say("Token not found in database")
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
            ngx.log(ngx.INFO, "token value ----------> : ", cjson.encode(token))
            validate_token(token, config.bearer_tokens_option, config.mssql_options)
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