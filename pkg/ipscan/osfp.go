package ipscan

import (
	"time"

	"github.com/go-ping/ping"
)

var (
	OSDB = map[int]string{
		//64:  {"Linux", "FreeBSD", "Centos", "Ubuntu"},
		//128: {"Windows XP", "Windows 7", "Windows 10", "Windows Server 2012 R2", "Windows Server 2019", "Windows Server 2016"},
		//256: {"Symbian", "Palm OS", "Cisco IOS", "Debain"},
		64:  "Linux",
		128: "Windows",
		256: "Unknown",
	}
)

func CheckOS(ip string) (os string, err error) {
	var ttl int
	pinger, err := ping.NewPinger(ip) // nolint
	pinger.Count = 2
	pinger.Timeout = 3 * time.Second
	pinger.OnRecv = func(packet *ping.Packet) {
		ttl = packet.Ttl
	}
	err = pinger.Run() // blocks until finished
	if err != nil {
		return
	}
	if ttl <= 64 && ttl > 32 {
		ttl = 64
	} else if ttl > 64 && ttl <= 128 {
		ttl = 128
	} else if ttl > 128 && int(ttl) <= 256 {
		ttl = 256
	}
	os = OSDB[ttl]
	return
}
