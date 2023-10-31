package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

const KPROBE_DO_FORK string = "do_fork"
const KPROBE_EXECVE string = "execve"
const KPROBE_EXIT string = "exit"

func ain() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

}
