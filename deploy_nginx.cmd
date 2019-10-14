docker rm -f nginx_lua_lb_server
docker rmi -f nginx_lua

docker build -t nginx_lua .

docker run -d --name redis_db -p 6379:6379 redis
docker run -d --name nginx_lua_lb_server -p 80:80 nginx_lua
