/*
*    Go Network Monitor - personal project
*    Released under the MIT License:  https://gherlein.mit-license.org/
 */

package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/coreos/go-systemd/daemon"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/onsi/gocleanup"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/viper"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type node struct {
	hostname string
	addr     string
	IP       net.IP
	incount  uint64
	outcount uint64
}

var (
	cli         bool   = true
	logfile     string = "/var/log/gonetmon.log"
	f           *os.File
	device      string = ""
	cidr        string = ""
	port        string = ""
	snapshotLen int32  = 1024
	promiscuous bool   = true
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
	nodes       []node
	debug       bool = false
	debug2      bool = false
	netBytes         = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "network_bytes_total",
		Help: "Number of bytes seen on the network.",
	})
	nodeBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "node_bytes_total",
			Help: "Number of bytes seen on that network node.",
		},
		[]string{"device"},
	)
)

func init() {

	flag.StringVar(&device, "device", "", "name of the network device to monitor")
	flag.StringVar(&cidr, "cidr", "", "CIDR of the network device to monitor")
	flag.StringVar(&port, "port", "", "port on localhost that metrics will be exported on")
	flag.Parse()

	// if there were no command line params, read from the config file
	if device == "" || cidr == "" || port == "" {
		cli = false
		viper.SetConfigName("gonetmon") // no need to include file extension
		viper.AddConfigPath(".")
		viper.AddConfigPath("/etc/")

		err := viper.ReadInConfig()
		if err != nil {

		} else {
			device = viper.GetString("network.device")
			cidr = viper.GetString("network.cidr")
			port = viper.GetString("exporter.port")
		}
	}
	prometheus.MustRegister(netBytes)
	prometheus.MustRegister(nodeBytes)
}

func calcNetwork(d string, c string) (int, string, error) {
	var (
		mask     net.IPMask
		masklen  int
		numhosts int
		baseaddr string
	)
	ipv4Addr, ipv4Net, err := net.ParseCIDR(c)
	if err != nil {
		log.Fatal(err)
		return 0, "", err
	}

	mask = ipv4Addr.DefaultMask()
	masklen, _ = mask.Size()
	numhosts = int(math.Pow(2, float64(32-masklen)))
	baseaddr = strings.TrimSuffix(ipv4Addr.String(), ".0")

	if debug {
		fmt.Println(ipv4Addr)
		fmt.Println(ipv4Net)
		fmt.Println(numhosts)
		fmt.Println(baseaddr)
		fmt.Println(c)
	}
	return numhosts, baseaddr, nil
}

func main() {

	var (
		numhosts int
		baseaddr string
	)

	if device == "" || cidr == "" || port == "" {
		fmt.Printf("device name and/or cidr and/or port not specified\n")
		os.Exit(3)
	}
	if cli == false {
		//create your file with desired read/write permissions
		f, err := os.OpenFile(logfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Fatal(err)
		}
		log.SetOutput(f)
		defer func() {
			log.Println("exiting")
			f.Sync()
			f.Close()
		}()
	}

	numhosts, baseaddr, err = calcNetwork(device, cidr)

	log.Printf("Startup - Device: %s - CIDR: %s - numhosts: %d - baseaddr: %s - port %s\n",
		device,
		cidr,
		numhosts,
		baseaddr,
		port)

	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	gocleanup.Register(printStats)

	for x := 0; x < numhosts; x++ {
		if x == 0 {
			continue
		}
		addr := fmt.Sprintf("%s.%d", baseaddr, x)
		names, err := net.LookupAddr(addr)
		var hostname string
		if err != nil || len(names) == 0 {
			hostname = fmt.Sprintf("unknown-%s", addr)
			if debug {
				fmt.Printf("%s - %s\n", addr, hostname)
			}
		} else {
			hostname = names[0]
			if debug {
				fmt.Printf("%s - %s\n", addr, hostname)
			}
		}

		nodes = append(nodes,
			node{IP: net.ParseIP(addr),
				addr:     addr,
				hostname: hostname,
				incount:  0,
				outcount: 0,
			})
	}

	if debug2 {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Press any key to continue...")
		text, _ := reader.ReadString('\n')
		fmt.Println(text)
	}

	ticker := time.NewTicker(time.Minute)
	go func() {
		for t := range ticker.C {
			logStats()
			clearStats()
			_ = t
			if debug {
				printStats()
			}

		}
	}()

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		url := fmt.Sprintf(":%s", port)
		log.Fatal(http.ListenAndServe(url, nil))
	}()

	daemon.SdNotify(false, "READY=1")

	ticker2 := time.NewTicker(time.Second * 15)
	go func() {
		for t := range ticker2.C {
			_ = t
			url := fmt.Sprintf("http://localhost:%s/metrics", port)
			_, err := http.Get(url)
			if err != nil {
				log.Println("internal health check failed")
			} else {
				daemon.SdNotify(false, "WATCHDOG=1")
			}
		}
	}()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		//printPacketInfo(packet)
		analyzePacket(packet)
	}

}

func analyzePacket(packet gopacket.Packet) {

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		netBytes.Add(float64(ip.Length))
		for i, node := range nodes {
			if node.addr != "" {
				if node.IP.Equal(ip.SrcIP) {
					nodeBytes.With(prometheus.Labels{"device": node.hostname}).Add(float64(ip.Length))
					nodes[i].outcount += uint64(ip.Length)
					if debug {
						fmt.Printf("From %s to %s - len %d\n", node.hostname, ip.DstIP, ip.Length)
					}
				}
				if node.IP.Equal(ip.DstIP) {
					nodeBytes.With(prometheus.Labels{"device": node.hostname}).Add(float64(ip.Length))
					nodes[i].incount += uint64(ip.Length)
					if debug {
						fmt.Printf("From %s to %s - len %d\n", ip.SrcIP, node.hostname, ip.Length)
					}
				}
			}

		}
	}
}

func printStats() {
	log.Printf("------------------- Summary Stats ------------------- \n")
	for _, node := range nodes {
		if node.incount != 0 && node.outcount != 0 {
			log.Printf("%-16s   %-30s    %-10.1fk    %-10.1fk\n",
				node.addr,
				node.hostname,
				float64(node.incount)/1000,
				float64(node.outcount)/1000)
		}
	}
	f.Sync()
}

func logStats() {
	log.Printf("------------------- Summary Stats ------------------- \n")
	for _, node := range nodes {
		if node.incount != 0 && node.outcount != 0 {
			log.Printf("%-16s   %-30s    %-10.1fk    %-10.1fk\n",
				node.addr,
				node.hostname,
				float64(node.incount)/1000,
				float64(node.outcount)/1000)
		}
	}
	f.Sync()
}

func clearStats() {
	for i, _ := range nodes {
		nodes[i].incount = 0
		nodes[i].outcount = 0
	}
}
