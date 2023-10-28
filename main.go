package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	internetIsAvailable := false

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for ; !internetIsAvailable; <-ticker.C {

		cmd := exec.Command("ping", "-c 1", "8.8.8.8")
		cmdOutput, err := cmd.CombinedOutput()

		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot check if internet is available: %s\n", err)
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
	// networkCapture()
	processWatch()

}

func networkCapture() {
	openDevice := inUseInternetDeviceInterface()

	var wg sync.WaitGroup
	wg.Add(len(openDevice))

	for _, device := range openDevice {
		newDevice := device
		if handle := openNetworkDevice(newDevice); handle != nil {
			newHandle := handle

			go func(handle *pcap.Handle, wg *sync.WaitGroup, device string) {
				defer wg.Done()
				defer handle.Close()

				packSource := gopacket.NewPacketSource(handle, handle.LinkType())
				for packet := range packSource.Packets() {

					// Handle IPv6 layer.
					if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
						ip6, _ := ip6Layer.(*layers.IPv6)
						fmt.Printf("%s\n", strings.Repeat("-", 7))
						fmt.Printf("IPv6: %s -> %s\n", ip6.SrcIP, ip6.DstIP)
						fmt.Printf("packet from device: %s, the cost of fetching this packet is %d bytes\n", newDevice, packet.Metadata().Length)
						fmt.Printf("%s\n", strings.Repeat("-", 7))
					} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
						// Handle ICMP layer.
						icmp4, _ := icmpLayer.(*layers.ICMPv4)
						fmt.Printf("%s\n", strings.Repeat("-", 7))
						fmt.Printf("ICMP: Type %d Code %d\n", icmp4.TypeCode.Type(), icmp4.TypeCode.Code())
						fmt.Printf("packet from device: %s, the cost of fetching this packet is %d bytes\n", newDevice, packet.Metadata().Length)
						fmt.Printf("%s\n", strings.Repeat("-", 7))
					} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
						// Handle UDP layer.
						udp, _ := udpLayer.(*layers.UDP)
						fmt.Printf("%s\n", strings.Repeat("-", 7))
						fmt.Printf("UDP: %d -> %d\n", udp.SrcPort, udp.DstPort)
						fmt.Printf("packet from device: %s, the cost of fetching this packet is %d bytes\n", newDevice, packet.Metadata().Length)
						fmt.Printf("%s\n", strings.Repeat("-", 7))

					} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
						tcp, _ := tcpLayer.(*layers.TCP)
						fmt.Printf("%s\n", strings.Repeat("-", 7))
						fmt.Printf("TCP: 😎%d -> %d Sequence number : %d \n", tcp.SrcPort, tcp.DstPort, tcp.Seq)
						fmt.Printf("packet from device: %s, the cost of fetching this packet is %d bytes\n", newDevice, packet.Metadata().Length)
						fmt.Printf("%s\n", strings.Repeat("-", 7))

					} else if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
						// Handle IPv4 layer.
						ip4, _ := ip4Layer.(*layers.IPv4)
						fmt.Printf("%s\n", strings.Repeat("-", 7))
						fmt.Printf("IPv4 😊: %s -> %s protocol %s\n", ip4.SrcIP, ip4.DstIP, ip4.Protocol)
						fmt.Printf("packet from device: %s, the cost of fetching this packet is %d bytes\n", newDevice, packet.Metadata().Length)
						fmt.Printf("%s\n", strings.Repeat("-", 7))
					} else {
						// Handle other cases.
						fmt.Printf("\n%sOTHER TYPE OF PACKET%s\n", strings.Repeat("-", 7), strings.Repeat("-", 7))

					}
				}

			}(newHandle, &wg, newDevice)
		}
	}

	wg.Wait()

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

func processWatch() {

}

func validateInode(inodeNumber string) int {

	pattern := `^\d+$`
	var (
		inodeNo int
		err     error
	)
	compiledPattern := regexp.MustCompile(pattern)
	if match := compiledPattern.MatchString(inodeNumber); !match {
		return -1
	}
	if inodeNo, err = strconv.Atoi(inodeNumber); err != nil {
		return -1
	}
	return inodeNo

}
func NoOflinesInFile(filePath string, ch chan<- intChannelResponse) {
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		ch <- intChannelResponse{0, err}
	}
	ch <- intChannelResponse{len(strings.Split(string(fileContent), "\n")),
		nil}
}

func processesOnTCP(networkType string) ([]string, error) {

	getLinelength := make(chan intChannelResponse)
	go NoOflinesInFile(networkType, getLinelength)

	file, err := os.Open(networkType)
	if err != nil {
		return nil, fmt.Errorf("could not open system process at %s: ERROR: %s", networkType, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue // This line doesn't have enough fields, skip it
		}
		inode := fields[9]
		fmt.Println("Inode:", inode)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("error reading file:", err)
	}
	return nil, nil
}

type intChannelResponse struct {
	Result int
	Error  error
}
