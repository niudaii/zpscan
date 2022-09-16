package domainscan

import (
	"net"
	"strings"
)

func (r *Runner) CheckCDN(ip string) bool {
	if strings.Contains(ip, "CNAME") {
		for _, name := range r.options.CdnCnameData {
			if strings.Contains(ip, name) {
				return true
			}
		}
	} else {
		for _, cidr := range r.options.CdnIpData {
			if IpContains(cidr, ip) {
				return true
			}
		}
	}
	return false
}

func IpContains(cidr string, ip string) bool {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ipAddr := net.ParseIP(ip)
	return ipnet.Contains(ipAddr)
}
