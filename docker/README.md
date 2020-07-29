# Mcast docker

## Run receiver

sudo docker run -ti olofhagsand/mcast sleep 3600
sudo docker exec -ti <id> mrcv 225.1.1.1:7878
or
sudo docker run -ti olofhagsand/mcast mrcv 225.1.1.1:7878

(find <id> with ps docker)

## Run sender

sudo docker exec -ti <id> mcast 225.1.1.1:7878

## Start test container in docker

sudo docker run -p 8080:80 --name mcast -it olofhagsand/mcast /usr/bin/start.sh

curl localhost:8080/cgi-bin/reply.sh

## Build

```
  sudo make docker
```

`make push` to push to upstream - if you have write access.