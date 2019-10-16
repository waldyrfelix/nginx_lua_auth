local jwt = require "resty.jwt"
local cjson = require "cjson"

local function check_token()
    -- verify if authorization header exists
    local jwt_token = ngx.var.http_authorization
    if not jwt_token then return false end

    -- verify if token is valid
    if string.len(jwt_token) < 32 then return false end

    if not string.match(jwt_token:lower(), "bearer") then return false end

    -- extract jwt token from authorization header
    jwt_token = string.sub(jwt_token, 8, -1)

    -- verify jwt token and get object
    local jwt_key = os.getenv("JWT_KEY")
    local jwt_obj = jwt:verify(jwt_key, jwt_token)

    -- verify domain, tenant, subscriber and expiration
    if not jwt_obj.verified or jwt_obj.payload.dom ~= ngx.var.http_host then
        return false
    end

    -- print(cjson.encode( jwt_obj.payload ))

    ngx.var["linkapi_tenant"] = jwt_obj.payload.iss
    ngx.var["linkapi_subscriber"] =  jwt_obj.payload.sub
    ngx.var["linkapi_project"] =  jwt_obj.payload.pro
    ngx.var["linkapi_dependencies"] =  jwt_obj.payload.dep
    ngx.var["linkapi_client_id"] =  jwt_obj.payload.aud

    return true
end

local token = check_token()
if not token then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header.content_type = 'text/plain'
    ngx.say("HTTP 401 - Unauthorized")
end