package main

import (
	_ "github.com/KoHcoJlb/coredns-proxmox"
	_ "github.com/coredns/coredns/core/plugin"

	"github.com/coredns/coredns/coremain"
)

func main() {
	coremain.Run()
}
