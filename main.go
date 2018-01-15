package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/onsi/gocleanup"
	"log"
	//	"strings"
	"net"
	"time"
)

type node struct {
	addr     string
	IP       net.IP
	incount  uint64
	outcount uint64
}

var (
	device      string = "enp4s6"
	snapshotLen int32  = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
	nodes       []node
)

func main() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	gocleanup.Register(func() {
		fmt.Printf("------------------- Summary Stats ------------------- \n")
		for _, node := range nodes {
			fmt.Printf("%s: %d %d\n", node.addr, node.incount, node.outcount)
		}

	})

	nodes = append(nodes, node{addr: "192.168.2.11", incount: 0, outcount: 0})
	nodes = append(nodes, node{addr: "192.168.2.70", incount: 0, outcount: 0})

	for i, node := range nodes {
		nodes[i].IP = net.ParseIP(node.addr)
	}

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
					fmt.Printf("From %s to %s - len %d\n", ip.SrcIP, ip.DstIP, ip.Length)
				}
				if node.IP.Equal(ip.DstIP) {
					nodes[i].incount += uint64(ip.Length)
					fmt.Printf("From %s to %s - len %d\n", ip.SrcIP, ip.DstIP, ip.Length)
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
