# Mcast docker

## Build

```
  sudo make docker
```

`make push` to push to upstream - if you have write access.

## Start test server container in docker

This starts a small web-server on port 8080 and a udp test receiver on port 7878:
```
sudo docker run -p 7878:7878/udp -p 8080:80/tcp --name mrcv --rm -it olofhagsand/mcast /usr/bin/start.sh
```

Change ports to bind to others than 7878 and 8080 repsectively

## Run tests towards test container


Web tests from host:
```
  curl localhost:8080/cgi-bin/reply.sh
  curl localhost:8080/
```

UDP latency test from host and other container respectively:
```
./mcast 127.0.0.1:7878
sudo docker run -ti olofhagsand/mcast mcast <host ipaddr>:7878
```
Note if you run from other container you have to address it to the host local interface address (not localhost).
