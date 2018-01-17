package main

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/onsi/gocleanup"
	"log"
	"math"
	"net"
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
	device      string = "eth0"
	cidr        string = "192.168.1.1/24"
	mask        net.IPMask
	masklen     int
	numhosts    int
	baseaddr    string
	snapshotLen int32 = 1024
	promiscuous bool  = true
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
	nodes       []node
	debug       bool = true
)

func main() {

	if len(os.Args) == 2 {
		device = os.Args[1]
	}
	if len(os.Args) == 3 {
		device = os.Args[1]
		cidr = os.Args[2]
		ipv4Addr, ipv4Net, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatal(err)
		}

		mask = ipv4Addr.DefaultMask()
		masklen, _ = mask.Size()
		numhosts = int(math.Pow(2, float64(32-masklen)))
		baseaddr = strings.TrimSuffix(ipv4Addr.String(), ".0")

		fmt.Println(ipv4Addr)
		fmt.Println(ipv4Net)
		fmt.Println(numhosts)
		fmt.Println(baseaddr)
		//		os.Exit(3)
	}

	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	gocleanup.Register(func() {
		fmt.Printf("------------------- Summary Stats ------------------- \n")
		for _, node := range nodes {
			if node.incount != 0 && node.outcount != 0 {
				fmt.Printf("%s: %d %d\n", node.addr, node.incount, node.outcount)
			}
		}

	})

	for x := 0; x < numhosts; x++ {
		if x == 0 {
			continue
		}
		addr := fmt.Sprintf("%s.%d", baseaddr, x)
		names, err := net.LookupAddr(addr)
		var hostname string
		if err != nil || len(names) == 0 {
			hostname = "unknown"
			fmt.Printf("%s - %s\n", addr, hostname)
		} else {
			hostname = names[0]
			fmt.Printf("%s - %s\n", addr, hostname)
		}
		nodes = append(nodes,
			node{IP: net.ParseIP(addr), addr: addr, hostname: hostname, incount: 0, outcount: 0})
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Press any key to continue...")
	text, _ := reader.ReadString('\n')
	fmt.Println(text)

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

		for i, node := range nodes {
			if node.addr != "" {
				if node.IP.Equal(ip.SrcIP) {
					nodes[i].outcount += uint64(ip.Length)
					if debug {
						fmt.Printf("From %s to %s - len %d\n", ip.SrcIP, ip.DstIP, ip.Length)
					}
				}
				if node.IP.Equal(ip.DstIP) {
					nodes[i].incount += uint64(ip.Length)
					if debug {
						fmt.Printf("From %s to %s - len %d\n", ip.SrcIP, ip.DstIP, ip.Length)
					}
				}
			}

		}
	}
}

func printPacketInfo(packet gopacket.Packet) {
	// Let's see if the packet is an ethernet packet    ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		//		fmt.Println("Ethernet layer detected.")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
		fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
		// Ethernet type is typically IPv4 but could be ARP or other
		//		fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
		//		fmt.Println()
	}

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		//		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP

		fmt.Printf("From %s to %s - len %d\n", ip.SrcIP, ip.DstIP, ip.Length)
		//		fmt.Println("Protocol: ", ip.Protocol)
		//		fmt.Println()

	}

	// Let's see if the packet is TCP    tcpLayer := packet.Layer(layers.LayerTypeTCP)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		//		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)

		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		//		fmt.Println("Sequence number: ", tcp.Seq)
		//		fmt.Println()
	}
	fmt.Println()

	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the Payload    applicationLayer := packet.ApplicationLayer()
	//	applicationLayer := packet.ApplicationLayer()
	//	if applicationLayer != nil {
	//		fmt.Println("Application layer/Payload found.")
	//		fmt.Printf("%s\n", applicationLayer.Payload())

	// Search for a string inside the Payload        if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
	//		fmt.Println("HTTP found!")
	//	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}
