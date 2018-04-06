# GoNetMon

![Grafana Image](/images/grafana.png)

## What?

This is a tool I want for my own home network.  It's a systemd-controlled daemon that collects per-host network use and exports it to Prometheus, which in turn is graphed on Grafana.

## Why?

I am learning golang and wanted someting real to build.  Plus, I
really want to see what is putting traffic on my network.  Yes, I
could have just used an off the shelf thing, but did I mention I
wanted to learn golang/Prometheus/Grafana?

## Setup

### Configure a Network Interface for Sniffing

To use this you will need to configure an interface for sniffing.  I
did this by setting up my main network switch (a Netgear GS116E) to
port mirror all ports to port 1, and wired port 1 to a second NIC on
an Ubuntu linux box.  Note:  I recommend you use Gigabit Ethernet.

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

### Seeing All the Network Traffic

Sniffing a port on a switch will not show you all the traffic.  That's just not how switches work.  To get visibility into all the traffic I use a switch that supports "port mirroring."  I like the Netgear GS108E (and relatives) even though it needs a Winblows app to configure them until you set up their local web page.

### Reverse DNS

Gonetmon will use reverse DNS to get human-readable names for each IP address in the CIDR block that it monitors.  If you don't configure that you will get device names that are IP addresses, which are not anywhere near as useful.  Configuring your DNS is outside the scope of this README.  For the lazy, here's a [link to some instructions](https://www.tecmint.com/install-dhcp-server-in-ubuntu-debian/).


### Gonetmon Configuration

Edit the gonetmon.toml file to reflect your network interface and CIDR:

```
[network]
device = "enp4s6"
cidr ="192.168.2.0/24"


[exporter]
port ="8080"
```
Use the network port you configured for sniffing and the CIDR for your own network, of course.  You will need the port number specified here when you configure Prometheus (see below).

## Build

Use the handy makefile:

```
make 
```
You almost certainly are going to have to install the dependencies.


### Gonetmon Installation

Use the handy makefile:

```
make install 
```

This will install the systemd files and actually enable and start it as a daemon.

### What if I don't have Systemd?

Sorry.  I'm on Ubuntu that has it and if I get time I'll do an installer for the older method.  Don't hold your breath though.  Pull Requests welcome!

### Gonetmon Behavior

The code will use the CIDR you pass in to find the number of POSSIBLE
hosts on the network and will watch them all as it processes packets.
It will do a reverse DNS lookup on each host to try to get a hostname.

Every minute it will collect the total bytes in and out for each IP
address and keep a running total.  It will dump a basic stats page
every minute for hosts that had any traffic that minute.

# Prometheus

## Configuration
Add a job to /etc/prometheus/prometheus.yaml:

```
scrape_configs:
  # The job name is added as a label `job=<job_name>` to any timeseries scraped from this config.
  <...snip...>

  - job_name: 'network_stats'
    static_configs:
      - targets: ['localhost:8080']

  <...snip...>
```

The port number specified in the target must be the same port number called out above in the gonetmon "port" configuration.

## Queries

The key parameter gonetmon exports is "node_bytes_total" and they are tagged by "device" which is poulated by reverse DNS lookup in gonetmon.  Here's a query to see all the traffic measured:

```
rate(node_bytes_total [5m])
```

This replies with rates across a 5 minute period derived from the underlying time-series data.


# Grafana

It's up to you to build your own dashboards, but to save you time I wanted to show a few graph queries that are useful in this context.

## Matching Hostnames

I name devices on my network with a naming convention.  For example, all my Amazon Alexa device hostnames start with the word "alexa" - examples:  alexalivingroom, alexakitchen, etc.  My Roku player is likewise named with roku as the start of it's hostname.  We use Alexa devices a lot to listen to music.  This let's me create a graph on my dashboard that displays all media player traffic using using this query:

```
rate(node_bytes_total {device=~"alexa.*|roku.*" } [5m] )
```

This query pulls the rates for devices whose names start with "alexa" OR "roku" and plots them.

You can build your own queries based on your own naming convention.

# Useful Links

[Creating Systemd Service Files](https://www.devdungeon.com/content/creating-systemd-service-files)
[Integration of a Go service with systemd: readiness & liveness](https://vincent.bernat.im/en/blog/2017-systemd-golang)
[Integration of a Go service with systemd: socket activation](https://vincent.bernat.im/en/blog/2018-systemd-golang-socket-activation)

# Gonetmon License

This project is released under the MIT License.  Please see details [here] (https://gherlein.mit-license.org).
