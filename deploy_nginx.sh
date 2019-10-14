docker rm -f nginx_lua_lb_server
docker rmi -f nginx_lua
docker build -t nginx_lua .
docker run -d --name nginx_lua_lb_server -p 80:80 nginx_lua
