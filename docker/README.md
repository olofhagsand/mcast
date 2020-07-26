# Mcast docker

## Run
sudo docker run -ti olofhagsand/mcast sleep 3600
sudo docker exec -ti 917bd2fa135e mrcv 225.1.1.1:7878
or
sudo docker run -ti olofhagsand/mcast mrcv 225.1.1.1:7878

# start test container in docker
sudo docker run -p 8080:80 -it localhost:5000/mcast /usr/bin/start.sh

curl localhost:8080/cgi-bin/reply.sh

## Build

```
  sudo make docker
```

`make push` to push to upstream - if you have write access.