local cjson = require "cjson"
local jwt = require "resty.jwt"
local redis = require "resty.redis"

local function subdomain()
    local domain = ngx.var.http_host
    local index = domain:find('.', 1, true)
    local subdomain = domain:sub(1, index - 1)
    return subdomain
end

local function authenticate()
    -- if ngx.req.get_method() ~= ngx.HTTP_POST then return false end

    ngx.req.read_body() -- explicitly read the req body
    local data = ngx.req.get_body_data()
    if not data then return false end

    local obj_data = cjson.decode(data)
    if not obj_data then return false end

    if not obj_data.client_id or not obj_data.client_secret then return false end

    local redis_key = string.format("%s:%s:%s", subdomain(), obj_data.client_id,
                                    obj_data.client_secret)

    local redis_conn = redis:new()
    redis_conn:set_timeouts(100, 100, 100) -- 100ms

    local ok, err = redis_conn:connect(os.getenv("REDIS_HOST"),
                                       os.getenv("REDIS_PORT"))
    if not ok then
        ngx.log(ngx.STDERR, "redis connection problem: ", err)
        return false
    end

    local props, err = redis_conn:hmget(redis_key, "tenant", "subscriber")
    redis_conn:close()

    if not props then
        ngx.log(ngx.ERR, "failed to get redis key: ", redis_key, ", ", err)
        return false
    end

    if props[1] == ngx.null or props[2] == ngx.null then
        ngx.log(ngx.NOTICE, "redis key not found: ", redis_key)
        return false
    end

    return {
        client_id = obj_data.client_id,
        tenant = props[1],
        subscriber = props[2]
    }
end

local function generate_token(user)
    local exp_token = 60 * 60
    local jwt_key = os.getenv("JWT_KEY")

    local jwt_token = jwt:sign(jwt_key, {
        header = {typ = "JWT", alg = "HS256"},
        payload = {
            sub = user.subscriber, -- subject
            iss = user.tenant, -- issuer
            aud = user.client_id, -- audience
            iat = os.time(), -- issued at
            exp = os.time() + exp_token -- expires
        }
    })

    return {access_token = jwt_token, expires_in = exp_token}
end

local user = authenticate()
if user then
    local token = generate_token(user)
    ngx.header.content_type = "application/json"
    ngx.say(cjson.encode(token))
else
    ngx.header.content_type = 'text/plain'
    ngx.status = ngx.HTTP_BAD_REQUEST
    ngx.say("HTTP 400 - Bad request")
end
