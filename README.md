This is mcast. A very simple traffic generator for UDP/IP uni and multi-cast.
for IP multicast, although it is useful for unicast too.

Mcast is under the GNU license, see the file COPYING, and is copyright
under its authors.  

Mcast is implemented by Olof Hagsand.

Mcast consists of two applications residing in one file each: 
	mcast.c - Traffic generator 
	mrcv.c  - Traffic receiver

The code is made to be as portable as possible. It should run on most
UNIXes, and used to run on Windows.

Example:
Start a receiver (this is not strictly necessary) on host foo:
foo> mrcv :7878

Start a sender with:
- duration 1 second, 
- 1000 Hz (packets-per-second)
- packet size (payload) 64 bytes
```
 local> mcast -p 1000 -s 64 -d 1 foo:7878
 local: Sending to 13.24.15.176:7878
        pkt_size= 64 (total = 92), duration = 1 s, period = 1000 us
 1.000003 s,  999.997000 pps
 mcast done, 1000 packets sent from local to 13.24.15.176
```


