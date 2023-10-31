package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func mai() {
	internetIsAvailable := false

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for ; !internetIsAvailable; <-ticker.C {

		cmd := exec.Command("ping", "-c 1", "8.8.8.8")
		cmdOutput, err := cmd.CombinedOutput()

		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot check if internet is available")
			continue
		}

		stringCmdOutput := string(cmdOutput)
		if strings.Contains(stringCmdOutput, "ping: connect: Network is unreachable") { // No internet connection...
			fmt.Println("no internet")
			continue
		}

		if strings.Contains(stringCmdOutput, "1 packets transmitted, 1 received") { // hurray!!!, internet here we go...
			internetIsAvailable = true
		}

	}

	ticker.Stop()
	networkCapture()
}

func networkCapture() int {
	openDevice := inUseInternetDeviceInterface()

	var wg sync.WaitGroup
	wg.Add(len(openDevice))

	count := 0
	for _, device := range openDevice {
		newDevice := device
		if handle := openNetworkDevice(newDevice); handle != nil {
			newHandle := handle

			count++
			fmt.Printf("\n%d is fired.\n", count)
			go func(handle *pcap.Handle, wg *sync.WaitGroup, device string) {
				defer func() {
					fmt.Println("this goroutine is comming to it end")
				}()
				defer wg.Done()
				defer handle.Close()

				packSource := gopacket.NewPacketSource(handle, handle.LinkType())
				for packet := range packSource.Packets() {

					var (
						srcIP      string
						dstIP      string
						protocol   string
						srcPort    string
						dstPort    string
						packetSize = packet.Metadata().Length
					)

					// Handle IPv4 layer.
					if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
						ip4, _ := ip4Layer.(*layers.IPv4)

						srcIP = ip4.SrcIP.String()
						dstIP = ip4.DstIP.String()
						protocol = ip4.Protocol.String()

						// Handle IPv6 layer.
					} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
						ip6, _ := ip6Layer.(*layers.IPv6)

						srcIP = ip6.SrcIP.String()
						dstIP = ip6.DstIP.String()
						protocol = ip6.NextHeader.String()

						// Unknown
					} else {
						fmt.Printf("\n%s\nOTHER TYPE OF PACKET: \n%+v\n %s\n", strings.Repeat("-", 20), packet, strings.Repeat("-", 20))
						continue
					}

					portInfo := handleTransportLayer(packet)
					srcPort = portInfo.SrcPort
					dstPort = portInfo.DstPort

					fmt.Printf("%s\n", strings.Repeat("-", 7))
					fmt.Printf("%s 😊: src :%s:%s -> dst: %s:%s\n", protocol, srcIP, srcPort, dstIP, dstPort)
					fmt.Printf("packet from device: %s, the cost of fetching this packet is %d bytes\n", newDevice, packetSize)
					fmt.Printf("%s\n", strings.Repeat("-", 7))

				}

			}(newHandle, &wg, newDevice)
		}
		fmt.Printf("Goroutine for device interface: %s, is fired and polling\n", device)
	}

	fmt.Printf("waiting on %d interface\n", len(openDevice))
	wg.Wait()
	fmt.Println("Got to the end")
	return count
}

type portInformation struct {
	SrcPort, DstPort string
}

func handleTransportLayer(packet gopacket.Packet) portInformation {

	// Handle TCP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)

		return portInformation{strconv.Itoa(int(tcp.SrcPort)), strconv.Itoa(int(tcp.DstPort))}
	}

	// Handle UDP layer.
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)

		return portInformation{strconv.Itoa(int(udp.SrcPort)), strconv.Itoa(int(udp.DstPort))}
	}

	return portInformation{"NO-SOURCE-PORT", "NO-DEST-PORT"}
}
func inUseInternetDeviceInterface() []string {
	cmd := exec.Command("sh", "-c", "ip route | awk '/default/ {print $5}'") // ip route | awk '/default/ {print $5}'
	cmdOutput, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot determine network interface for internet: %s", err)
		os.Exit(1)
	}
	return strings.Split(strings.TrimSpace(string(cmdOutput)), "\n")

}

func openNetworkDevice(device string) *pcap.Handle {
	handle, err := pcap.OpenLive(device, 1024, false, pcap.BlockForever)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open network device interface %s: ERROR: %s", device, err)
	}
	return handle
}


