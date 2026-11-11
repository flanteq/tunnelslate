package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"

	"tunnelslate/internal/statswire"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "VPN statistics:", err)
		os.Exit(1)
	}
}
func number(key string) int64 { n, _ := strconv.ParseInt(os.Getenv(key), 10, 64); return n }
func run() error {
	// The supervisor is root; all persistent statistics belong to the same UID as
	// OpenVPN's scripts and the unprivileged panel.
	if os.Geteuid() == 0 {
		if err := syscall.Setgroups([]int{10001}); err != nil {
			return err
		}
		if err := syscall.Setgid(10001); err != nil {
			return err
		}
		if err := syscall.Setuid(10001); err != nil {
			return err
		}
	}
	c := statswire.Collector{Queue: "/run/tunnelslate/statistics", Runtime: "/run/openvpn/statistics"}
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: vpn-stats start|sample|connect|disconnect|stop")
	}
	switch os.Args[1] {
	case "start":
		return c.Start()
	case "stop":
		return c.Stop()
	case "sample":
		b, err := os.ReadFile("/run/openvpn/status.log")
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return c.Sample(string(b))
	case "connect":
		started := number("time_unix")
		if started == 0 {
			started = time.Now().Unix()
		}
		return c.Connect(os.Getenv("common_name"), started)
	case "disconnect":
		return c.Disconnect(os.Getenv("common_name"), 0, time.Now().Unix(), number("bytes_sent"), number("bytes_received"))
	}
	return fmt.Errorf("unknown statistics command")
}
