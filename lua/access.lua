local cjson = require "cjson"
local jwt = require "resty.jwt"

local function not_authorized()
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header.content_type = 'text/plain'
    ngx.say("Access Denied. HTTP 401 - Unauthorized")
end

-- verify if authorization header exists
local jwt_token = ngx.var.http_authorization
if not jwt_token then
    not_authorized()
    return
end

-- verify if token is valid
if string.len(jwt_token) < 32 then
    not_authorized()
    return
end

if not string.match(jwt_token:lower(), "bearer") then
    not_authorized()
    return
end

-- extract jwt token from authorization header
jwt_token = string.sub(jwt_token, 8, -1)

-- verify jwt token and get object
local jwt_obj = jwt:verify("lua-resty-jwt", jwt_token)
if not jwt_obj or not jwt_obj.payload then
    not_authorized()
    return
end

-- get client id and verify against the redis database
local client_id = jwt_obj.payload.client_id
-- TODO: access redis db
if not client_id then
    not_authorized()
    return
end