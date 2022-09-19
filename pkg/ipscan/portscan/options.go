package portscan

import (
	"github.com/niudaii/zpscan/pkg/ipscan/portscan/privileges"
	"github.com/projectdiscovery/gologger"
)

type Options struct {
	Stdin      bool     // Stdin specifies whether stdin input was given to the process
	Verify     bool     // Verify is used to check if the ports found were valid using CONNECT method
	Debug      bool     // Prints out debug information
	Retries    int      // Retries is the number of retries for the port Retries 是端口的重试次数
	Rate       int      // Rate is the rate of port scan requests	扫描速率
	Timeout    int      // Timeout is the seconds to wait for ports to respond 超时时间
	Host       []string // Host is the single host or comma-separated list of hosts to find ports for
	Ports      string   // Ports is the ports to use for enumeration
	TopPorts   string   // Tops ports to scan
	SourceIP   string   // SourceIP to use in TCP packets
	Interface  string   // Interface to use for TCP packets
	Threads    int      // Internal worker threads
	ScanAllIPS bool     // Scan all the ips
	ScanType   string   // Scan Type
	Proxy      string   // Socks5 proxy
}

// ShowNetworkCapabilities 判断运行用户可能的网络功能/扫描类型
func (o *Options) ShowNetworkCapabilities(options *Options) {
	accessLevel := "no root"
	scanType := "CONNECT"
	if privileges.IsPrivileged && options.ScanType == SynScan {
		accessLevel = "root"
		if isLinux() {
			accessLevel = "CAP_NET_RAW"
		}

		scanType = "SYN"
	}
	gologger.Info().Msgf("%s scan with %s\n", scanType, accessLevel)
}
