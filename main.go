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

func main() {
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
	_ = networkCapture()
	fmt.Println("CAPTURE ENDED")
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
						ip6, _ := ip6Layer.(*layers.IPv4)

						srcIP = ip6.SrcIP.String()
						dstIP = ip6.DstIP.String()
						protocol = ip6.Protocol.String()

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
	return 1
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

// func processWatch() {

// }

// func validateInode(inodeNumber string) int {

// 	pattern := `^\d+$`
// 	var (
// 		inodeNo int
// 		err     error
// 	)
// 	compiledPattern := regexp.MustCompile(pattern)
// 	if match := compiledPattern.MatchString(inodeNumber); !match {
// 		return -1
// 	}
// 	if inodeNo, err = strconv.Atoi(inodeNumber); err != nil {
// 		return -1
// 	}
// 	return inodeNo

// }
// func NoOflinesInFile(filePath string, ch chan<- intChannelResponse) {
// 	fileContent, err := os.ReadFile(filePath)
// 	if err != nil {
// 		ch <- intChannelResponse{0, err}
// 	}
// 	ch <- intChannelResponse{len(strings.Split(string(fileContent), "\n")),
// 		nil}
// }

// func processesOnTCP(networkType string) ([]string, error) {

// 	getLinelength := make(chan intChannelResponse)
// 	go NoOflinesInFile(networkType, getLinelength)

// 	file, err := os.Open(networkType)
// 	if err != nil {
// 		return nil, fmt.Errorf("could not open system process at %s: ERROR: %s", networkType, err)
// 	}
// 	defer file.Close()

// 	scanner := bufio.NewScanner(file)
// 	for scanner.Scan() {
// 		line := scanner.Text()
// 		fields := strings.Fields(line)
// 		if len(fields) < 10 {
// 			continue // This line doesn't have enough fields, skip it
// 		}
// 		inode := fields[9]
// 		fmt.Println("Inode:", inode)
// 	}

// 	if err := scanner.Err(); err != nil {
// 		fmt.Println("error reading file:", err)
// 	}
// 	return nil, nil
// }

// type intChannelResponse struct {
// 	Result int
// 	Error  error
// }
