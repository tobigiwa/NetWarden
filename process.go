package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	stringPathToPRocNetFiles = "/proc/net/"
	globaPatternMatchForIPv4 = "*[tu][cd][p]"
	globaPatternMatchForIPv6 = "*[tu][cd][p]6"

	globPattern = "/proc/net/{tcp*,udp*}"
)

// func main() {

// 	d := netStat()

// 	fmt.Printf("Proto %16s %20s %14s %24s\n", "Local Adress", "Foregin Adress",
// 		"State", "Pid/Program")

// 	for _, p := range d {
// 		ip_port := fmt.Sprintf("%v:%v", p.Ip, p.Port)
// 		fip_port := fmt.Sprintf("%v:%v", p.ForeignIp, p.ForeignPort)
// 		pid_program := fmt.Sprintf("%v/%v", p.Pid, p.Name)
// 		fmt.Printf("- %16v %20v %16v %20v\n", ip_port, fip_port,
// 			p.State, pid_program)
// 	}
// }

func netStat() []Process {

	networkData := readProcNetFile(procNetfilePaths())
	Processes := make([]Process, len(networkData))
	res := make(chan Process, len(networkData))

	currProcesses := getAllCurrProcess()

	for _, line := range networkData {
		go correlateProcessToSocket(line, &currProcesses, res)
	}

	for i := range networkData {
		p := <-res
		Processes[i] = p
	}

	return Processes
}

func readProcNetFile(filepaths []string) []string {

	container := make([]string, 0, 20)
	for _, filepath := range filepaths {
		data, err := os.ReadFile(filepath)
		if err != nil {
			panic(err)
		}
		lines := strings.Split(string(data), "\n")
		noHeadr := lines[1 : len(lines)-1]
		container = append(container, noHeadr...)
	}

	return container[2:]
}

func procNetfilePaths() []string {

	var filePaths []string
	tcpAndudp, _ := filepath.Glob(filepath.Join("/proc/net/", globaPatternMatchForIPv4))
	tcp6Andudp6, _ := filepath.Glob(filepath.Join("/proc/net/", globaPatternMatchForIPv6))
	filePaths = append(tcpAndudp, tcp6Andudp6...)

	return filePaths
}

func currProcessDescriptors() []string {
	descriptors, err := filepath.Glob("/proc/[0-9]*/fd/[0-9]*")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return descriptors
}

func getAllCurrProcess() []processInode {
	allProcessDescriptors := currProcessDescriptors()
	allProcessInodes := make([]processInode, 0, len(allProcessDescriptors))
	rec := make(chan processInode, len(allProcessDescriptors))

	go func(processDescriptor *[]string, ch chan<- processInode) {
		for _, processPath := range *processDescriptor {
			symlink, _ := os.Readlink(processPath)
			ch <- processInode{processPath, symlink}
		}
	}(&allProcessDescriptors, rec)

	for range allProcessDescriptors {
		processInodesndPath := <-rec
		allProcessInodes = append(allProcessInodes, processInodesndPath)
	}

	return allProcessInodes
}

type processInode struct {
	path, symlink string
}

type Process struct {
	User        string
	Name        string
	Pid         string
	Exe         string
	State       string
	Ip          string
	Port        int64
	ForeignIp   string
	ForeignPort int64
}

func correlateProcessToSocket(socketLine string, allProcess *[]processInode, ch chan<- Process) {

	line_array := removeEmpty(strings.Split(strings.TrimSpace(socketLine), " "))
	ip_port := strings.Split(line_array[1], ":")

	// local ip and port
	ip := convertIp(ip_port[0])
	port := hexToDec(ip_port[1])

	// foreign ip and port
	fip_port := strings.Split(line_array[2], ":")
	fip := convertIp(fip_port[0])
	fport := hexToDec(fip_port[1])

	state := STATE[line_array[3]]
	uid := getUser(line_array[7])
	pid := findPid(line_array[9], allProcess)
	exe := getProcessExe(pid)
	name := getProcessName(pid)

	ch <- Process{uid, name, pid, exe, state, ip, port, fip, fport}

}
func removeEmpty(array []string) []string {
	// remove empty data from line
	var new_array []string
	for _, i := range array {
		if i != "" {
			new_array = append(new_array, i)
		}
	}
	return new_array
}

func convertIp(ip string) string {
	// Convert the ipv4 to decimal. Have to rearrange the ip because the
	// default value is in little Endian order.

	var out string

	// Check ip size if greater than 8 is a ipv6 type
	if len(ip) > 8 {
		i := []string{ip[30:32],
			ip[28:30],
			ip[26:28],
			ip[24:26],
			ip[22:24],
			ip[20:22],
			ip[18:20],
			ip[16:18],
			ip[14:16],
			ip[12:14],
			ip[10:12],
			ip[8:10],
			ip[6:8],
			ip[4:6],
			ip[2:4],
			ip[0:2]}
		out = fmt.Sprintf("%v%v:%v%v:%v%v:%v%v:%v%v:%v%v:%v%v:%v%v",
			i[14], i[15], i[13], i[12],
			i[10], i[11], i[8], i[9],
			i[6], i[7], i[4], i[5],
			i[2], i[3], i[0], i[1])

	} else {
		i := []int64{hexToDec(ip[6:8]),
			hexToDec(ip[4:6]),
			hexToDec(ip[2:4]),
			hexToDec(ip[0:2])}

		out = fmt.Sprintf("%v.%v.%v.%v", i[0], i[1], i[2], i[3])
	}
	return out
}

func hexToDec(h string) int64 {
	// convert hexadecimal to decimal.
	d, err := strconv.ParseInt(h, 16, 32)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return d
}

func getProcessExe(pid string) string {
	exe := fmt.Sprintf("/proc/%s/exe", pid)
	path, _ := os.Readlink(exe)
	return path
}

func getProcessName(pid string) string {
	processName, _ := os.ReadFile(fmt.Sprintf("/proc/%s/comm", pid))
	return strings.ToTitle(string(processName))

}

func getUser(uid string) string {
	u, err := user.LookupId(uid)
	if err != nil {
		return "Unknown"
	}
	return u.Username
}

var STATE = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

func findPid(inode string, processes *[]processInode) string {
	// Loop through all fd dirs of process on /proc to compare the inode and
	// get the pid.

	pid := "-"
	re := regexp.MustCompile(inode)
	for _, item := range *processes {
		out := re.FindString(item.symlink)
		if len(out) != 0 {
			pid = strings.Split(item.path, "/")[2]
		}
	}
	return pid
}
