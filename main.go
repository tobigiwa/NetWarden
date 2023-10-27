package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
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
	networkCapture()
	// processWatch()

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
				for packets := range packSource.Packets() {
					fmt.Printf("packet from device: %s\n%s\nthe cost of fetching this packet is %d bytes\n\n", newDevice, strings.Repeat("-", 17), packets.Metadata().Length)
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
