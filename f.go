package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func man() {
	// pids, err := os.ReadDir("/proc")
	// if err != nil {
	// 	panic(err)
	// }

	// for _, pid := range pids {
	// 	if !pid.IsDir() || pid.Name()[0] < '0' || pid.Name()[0] > '9' {
	// 		continue
	// 	}

	// 	fds, err := os.ReadDir(filepath.Join("/proc", pid.Name(), "fd"))
	// 	if err != nil {
	// 		continue
	// 	}

	// 	for _, fd := range fds {
	// 		link, _ := os.Readlink(filepath.Join("/proc", pid.Name(), "fd", fd.Name()))
	// 		fmt.Println(strings.Repeat("-", 7))
	// 		fmt.Println(link)
	// 		// fmt.Println(strings.Repeat("-", 12))
	// 		if strings.HasPrefix(link, "socket:[") {
	// 			// fmt.Println("Found process using socket:", pid.Name())
	// 		}
	// 	}
	// }
	run()
}

func run() {
	pids, err := os.ReadDir("/proc/net")
	if err != nil {
		panic(err)
	}

	for _, fd := range pids {
		link, _ := os.Readlink(filepath.Join("/proc", "4711", "fd", fd.Name()))
		if strings.HasPrefix(link, "socket:[") {
			fmt.Println(strings.Repeat("-", 7))
			fmt.Println(link)
			fmt.Println("Found process using socket:", fd.Name())
		}
	}
}
