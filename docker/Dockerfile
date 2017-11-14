# Makefile for MCAST.
#
# Copyright (C) 2001,2016 Olof Hagsand
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


FROM ubuntu:16.04
MAINTAINER Olof Hagsand <olof@hagsand.se>

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update 
RUN apt-get install -y apt-utils
RUN apt-get install -y iperf3
RUN apt-get install -y lsb-release
RUN apt-get install -y tcpdump
RUN apt-get install -y net-tools # ifconfig + netstat
RUN apt-get install -y iproute # ip command
RUN apt-get install -y inetutils-ping 
RUN apt-get install -y inetutils-traceroute
RUN apt-get install -y nmap
RUN apt-get install -y netcat
#RUN apt-get install -y software-properties-common # netperf needs multiverse
#RUN apt-cache search netperf


COPY mcast /usr/bin/
COPY mrcv /usr/bin/
COPY ncat /usr/bin/
COPY plugins/cycles /usr/bin/
COPY plugins/dhrystones /usr/bin/
COPY plugins/diskio_read /usr/bin/
COPY plugins/diskio_write /usr/bin/
COPY plugins/diskio_write_rnd /usr/bin/
COPY plugins/grideye_iwget /usr/bin/
COPY plugins/grideye_sysinfo /usr/bin/
COPY plugins/grideye_wlan /usr/bin/
COPY plugins/mem_read /usr/bin/
COPY netperf-2.7.0/src/netperf /usr/bin/
COPY netperf-2.7.0/src/netserver /usr/bin/

#ENTRYPOINT ["mcast"]






