# GoNetMon

## What?

This is a tool I want for my own home network.  Eventually it will
have a waterfall display GUI served to a browser, but I'm
incrementally adding things as I go. 

Right now it ticks at 1 minute intervals and dumps a byte count of the
active hosts on that network for that minute.

## Why?

I am learning golang and wanted someting real to build.  Plus, I
really want to see what is putting traffic on my network.  Yes, I
could have just used an off the shelf thing, but did I mention I
wanted to learn golang?

## Setup

To use this you will need to configure an interface for sniffing.  I
did this by setting up my main network switch (a Netgear GS116E) to
port mirror all ports to port 1, and wired port 1 to my monitoring
port on an Ubuntu linux box.  Note:  I recommend you use Gigabit
Ethernet.

I also configured the sniffing port to have no IP address.  My changes
to the /etc/network/interfaces file added this:

```
auto enp4s6
iface enp4s6 inet manual
      up ifconfig $IFACE -arp up
      up ip link set $IFACE promisc on
      down ip link set $IFACE promisc off
      down ifconfig $IFACE down

post-up ethtool -K enp4s6 gro off
post-up ethtool -K enp4s6 lro off
```

Note that your network interface name will depend on your system.


## Usage

After building, run the tool like this:

```
sudo ./gonetmon <interface-name> <cidr to sniff> 
```

So a real-world example using the interface I configured above is:

```
sudo ./gonetmon enp4s6 192.168.2.0/244
```


## Behavior

The code will use the CIDR you pass in to find the number of POSSIBLE
hosts on the network and will watch them all as it processes packets.
It will do a reverse DNS lookup on each host to try to get a hostname.

Every minute it will collect the total bytes in and out for each IP
address and keep a running total.  It will dump a basic stats page
every minute for hosts that had any traffic that minute.

