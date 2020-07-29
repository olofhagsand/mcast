# Makefile for MCAST.
#
# Copyright (C) 2001,2016,2020 Olof Hagsand
#
# This software is a part of Mcast. A very simple traffic generator
# and analyzer especially tuned for IP multicast, although it is
# useful for unicast too.
# Mcast is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#  Mcast is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with Mcast; see the file COPYING.

FROM alpine
MAINTAINER Olof Hagsand <olof@hagsand.se>

# Install tools (if two-step do this last)
RUN apk add --update iperf3 tcpdump
RUN apk add --update net-tools # ifconfig + netstat
RUN apk add --update nmap mini_httpd
RUN apk add --update curl

RUN mkdir /mcast
RUN mkdir /mcast/build

# clone and build mcast source 
WORKDIR /mcast
COPY mcast .

RUN apk add --update make build-base gcc
RUN ./configure --prefix=/mcast/build
RUN make
RUN make install

COPY start.sh start.sh

RUN install start.sh mcast mrcv /usr/bin


# For mini_httpd and mrcv
EXPOSE 80/tcp 7878/udp

# Run start script
CMD /usr/bin/start.sh
