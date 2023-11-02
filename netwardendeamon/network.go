/*
 * Copyright (c) 2023, Oluwatobi Giwa
 * All rights reserved.
 *
 * This software is licensed under the 3-Clause BSD License.
 * See the LICENSE file or visit https://opensource.org/license/bsd-3-clause/ for details.
 */
package netwardendeamon

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var allPacketReceived, allPacketAccounted, allPacketUnaccounted, allPacketLost, allPacketGet atomic.Int64

func Start() {

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Not all processes could be identified, you would need root priviledges.")
		os.Exit(1)
	}

	exit := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(exit, os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGSTOP, syscall.SIGINT)

	defer close(done)
	defer close(exit)

	go func() {
		<-exit
		done <- true
	}()

	CheckNetworkAvailable()

	startTime := time.Now()

	go networkCapture()

	<-done

	endTime := time.Now()
	timeDiff := endTime.Sub(startTime)

	account(timeDiff)
	return
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
				defer func() {
					fmt.Println("this goroutine is comming to it end")
				}()
				defer wg.Done()
				defer handle.Close()

				packSource := gopacket.NewPacketSource(handle, handle.LinkType())
				for packet := range packSource.Packets() {

					allPacketReceived.Add(1)

					var capturedPacket netowrkPacket
					capturedPacket.packetSize = packet.Metadata().Length

					// Handle IPv6 layer.
					if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
						ip6, _ := ip6Layer.(*layers.IPv6)

						capturedPacket.srcIP = ip6.SrcIP.String()
						capturedPacket.dstIP = ip6.DstIP.String()
						capturedPacket.protocol = ip6.NextHeader.String()

						portInfo := handleTransportLayer(packet)
						capturedPacket.srcPort = portInfo.SrcPort
						capturedPacket.dstPort = portInfo.DstPort

						go resolvePacketToProcess(capturedPacket)
						continue

						// Handle IPv4 layer.
					} else if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
						ip4, _ := ip4Layer.(*layers.IPv4)

						capturedPacket.srcIP = ip4.SrcIP.String()
						capturedPacket.dstIP = ip4.DstIP.String()
						capturedPacket.protocol = ip4.Protocol.String()

						portInfo := handleTransportLayer(packet)
						capturedPacket.srcPort = portInfo.SrcPort
						capturedPacket.dstPort = portInfo.DstPort

						go resolvePacketToProcess(capturedPacket)
						continue

						// Unknown
					} else {
						fmt.Printf("\n%s\nOTHER TYPE OF PACKET: \n%+v\n %s\n", strings.Repeat("#", 20), packet, strings.Repeat("#", 20))
						allPacketLost.Add(1)
						continue
					}
				}

			}(newHandle, &wg, newDevice)
		}
		fmt.Printf("Goroutine for device interface: %s, is fired and polling\n", device)
	}

	fmt.Printf("waiting on %d interface\n", len(openDevice))
	wg.Wait()

	fmt.Println("Got to the end")
}

func resolvePacketToProcess(capturedPacket netowrkPacket) {

	allPacketGet.Add(1)

	for _, p := range netStat() {
		if (capturedPacket.srcIP == p.Ip &&
			capturedPacket.srcPort == fmt.Sprintf("%d", p.Port) &&
			capturedPacket.dstIP == p.ForeignIp &&
			capturedPacket.dstPort == fmt.Sprintf("%d", p.ForeignPort)) || // request
			(capturedPacket.srcIP == p.ForeignIp &&
				capturedPacket.srcPort == fmt.Sprintf("%d", p.ForeignPort) &&
				capturedPacket.dstIP == p.Ip &&
				capturedPacket.dstPort == fmt.Sprintf("%d", p.Port)) { // response maybe...

			allPacketAccounted.Add(1)
			return
		}
	}

	allPacketUnaccounted.Add(1)
	return
}

func CheckNetworkAvailable() {
	
	internetIsAvailable := false
	
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	for ; !internetIsAvailable; <-ticker.C {
		
		cmd := exec.Command("ping", "-c 1", "8.8.8.8")
		cmdOutput, err := cmd.CombinedOutput()
		
		if err != nil {
			fmt.Fprintln(os.Stderr, "internet does seems not to be available")
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
	return
}

type portInformation struct {
	SrcPort, DstPort string
}

type netowrkPacket struct {
	protocol,
	srcIP,
	dstIP,
	srcPort,
	dstPort string
	packetSize int
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

func account(timeDiff time.Duration) {
	fmt.Printf("%s\n", strings.Repeat("-", 30))
	fmt.Printf("Percentage Accounted for: %d\n", percentageCalc(&allPacketAccounted, &allPacketGet))
	fmt.Printf("Percentage Unaccounted for: %d\n", percentageCalc(&allPacketUnaccounted, &allPacketGet))
	fmt.Printf("Percentage Lost for: %d\n", percentageCalc(&allPacketLost, &allPacketGet))
	fmt.Printf("All the packet we got %d\n", &allPacketReceived)
	fmt.Printf("%s", strings.Repeat("-", 30))
	fmt.Printf("TIME: %s\n", timeDiff)
}

func percentageCalc(dividend, divisor *atomic.Int64) int64 {
	fmt.Println(dividend, divisor)
	dividendValue := float64(dividend.Load())
	divisorValue := float64(divisor.Load())
	
	if divisorValue == 0 {
		return 0 // Handle division by zero to avoid NaN
	}
	
	return int64((dividendValue / divisorValue) * 100)
}

// fmt.Printf("%s\n", strings.Repeat("-", 15))
// fmt.Printf("packet protocol is %s\n", capturedPacket.protocol)
// fmt.Printf("this packet belongs to %s\n", strings.ToUpper(strings.TrimSpace(p.Name)))
// fmt.Printf("PROCESS SIDE: %s 😊: local :%s:%s -> foreign: %s:%s\n", p.Name, p.Ip, fmt.Sprintf("%d", p.Port), p.ForeignIp, fmt.Sprintf("%d", p.ForeignPort))
// fmt.Printf("PACKET SIDE :%s 😊: src :%s:%s -> dst: %s:%s of size %d\n", capturedPacket.protocol, capturedPacket.srcIP, capturedPacket.srcPort, capturedPacket.dstIP, capturedPacket.dstPort, capturedPacket.packetSize)
// fmt.Printf("%s\n\n\n", strings.Repeat("-", 15))


// fmt.Printf("PACKET WASTED %s\n%s 😊: src :%s:%s -> dst: %s:%s of size %d\n%s\n\n\n", strings.Repeat("*", 15), capturedPacket.protocol, capturedPacket.srcIP, capturedPacket.srcPort, capturedPacket.dstIP, capturedPacket.dstPort, capturedPacket.packetSize, strings.Repeat("*", 15))