package portscan

import (
	"fmt"
	"strings"

	"github.com/niudaii/zpscan/pkg/ipscan/portscan/scan"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ipranger"
	"github.com/projectdiscovery/iputil"
)

func (r *Runner) ParseTarget() error {
	r.Scanner.State = scan.Init
	err := r.AddTarget(r.Options.Host)
	if err != nil {
		gologger.Fatal().Msgf("addtarget: %v", err)
	}
	return nil
}

func (r *Runner) AddTarget(targets []string) error {
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil
		} else if ipranger.IsCidr(target) { // ipranger.IsCidr(target) 判断ip是否是一个段IP，例如：192.168.1.0/24 则返回true，否则返回false
			if err := r.Scanner.IPRanger.AddHostWithMetadata(target, "cidr"); err != nil {
				gologger.Warning().Msgf("%s\n", err)
			}
		} else if ipranger.IsIP(target) && !r.Scanner.IPRanger.Contains(target) { // ipranger.IsIP 判断是否IP，"192.168.0.1"返回true,如果是"192.168.0.1/24"返回false
			if err := r.Scanner.IPRanger.AddHostWithMetadata(target, "ip"); err != nil {
				gologger.Warning().Msgf("%s\n", err)
			}
		} else { // 处理URL扫描
			ips, err := r.GetIPFromUrl(target)
			if err != nil {
				return err
			}
			for _, ip := range ips {
				if err := r.Scanner.IPRanger.AddHostWithMetadata(ip, target); err != nil {
					gologger.Warning().Msgf("%s\n", err)
				}
			}
		}
	}
	return nil
}

// GetIPFromUrl 将URL转换为IP地址
func (r *Runner) GetIPFromUrl(target string) ([]string, error) {
	ips, err := r.host2ips(target)
	if err != nil {
		return []string{}, err
	}

	var (
		initialHosts []string
		hostIPS      []string
	)
	for _, ip := range ips {
		if !r.Scanner.IPRanger.Np.ValidateAddress(ip) {
			gologger.Warning().Msgf("Skipping host %s as ip %s was excluded\n", target, ip)
			continue
		}

		initialHosts = append(initialHosts, ip)
	}

	if len(initialHosts) == 0 {
		return []string{}, nil
	}

	// 当解析URL为多个IP时，如果开启ScanAllIPS则扫描所有IP，否则只扫描第一个IP
	if r.Options.ScanAllIPS {
		hostIPS = initialHosts
	} else {
		hostIPS = append(hostIPS, initialHosts[0])
	}

	for _, hostIP := range hostIPS {
		gologger.Debug().Msgf("Using host %s for enumeration\n", hostIP)
		if err := r.Scanner.IPRanger.AddHostWithMetadata(hostIP, target); err != nil {
			gologger.Warning().Msgf("%s\n", err)
		}
	}

	return hostIPS, nil
}

func (r *Runner) host2ips(target string) (targetIPs []string, err error) {
	if !iputil.IsIP(target) {
		var ips []string
		ips, err = r.dnsClient.Lookup(target)
		if err != nil {
			gologger.Warning().Msgf("Could not get IP for host: %s\n", target)
			return
		}
		for _, ip := range ips {
			if iputil.IsIPv4(ip) {
				targetIPs = append(targetIPs, ip)
			}
		}

		if len(targetIPs) == 0 {
			return targetIPs, fmt.Errorf("no IP addresses found for host: %s", target)
		}
	} else {
		targetIPs = append(targetIPs, target)
		gologger.Debug().Msgf("Found %d addresses for %s\n", len(targetIPs), target)
	}

	return
}
