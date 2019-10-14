function password_encode(password)
    local bcrypt = require 'bcrypt'
    return bcrypt.digest(password, 12)
end

function check_password(password, encoded_password)
    local bcrypt = require 'bcrypt'  
    return bcrypt.verify(password, encoded_password)
end


function get_user(username)
    --- Defaults

    local access_redis_host =  ngx.var.access_redis_host == ''
        and '127.0.0.1' or ngx.var.access_redis_host

    local access_redis_port = ngx.var.access_redis_port == ''
        and 6379 or ngx.var.access_redis_port

    local access_user_catalogue = ngx.var.access_user_catalogue == ''
        and 'nginx_catalogue:users' or ngx.var.access_user_catalogue

    --- 

    local redis = require "nginx.redis"
    local red = redis:new()

    red:set_timeout(100)

    local ok, err = red:connect(access_redis_host, access_redis_port)
        if not ok then
            ngx.log(ngx.ERR, "failed to connect to the redis server: ", err)
            ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        return
    end

    local res, err = red:hget(access_user_catalogue, username)

    if not res then
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        return
    end

    -- User is not found
    if res == ngx.null then
        return
    end

    return res
end


function authenticate()
    -- Test Authentication header is set and with a value
    local header = ngx.req.get_headers()['Authorization']
    if header == nil or header:find(" ") == nil then
        return false
    end

    local divider = header:find(' ')
    if header:sub(0, divider-1) ~= 'Basic' then
       return false
    end

    local auth = ngx.decode_base64(header:sub(divider+1))
    if auth == nil or auth:find(':') == nil then
        return false
    end

    divider = auth:find(':')
    local username = auth:sub(0, divider-1)
    local password = auth:sub(divider+1)

    local res = get_user(username)

    if res == nil then
        return false
    end

    if check_password(password, res) then
        return true
    end

    return false
end


-- local user = authenticate()


-- if not user then
--    ngx.header.content_type = 'text/plain'
--    ngx.header.www_authenticate = 'Basic realm=""'
--    ngx.status = ngx.HTTP_UNAUTHORIZED
--    ngx.say('401 Access Denied')
-- end

ngx.header.content_type = "application/json"
ngx.say('{ "access_token": "your access token", "expires": 3600 }')