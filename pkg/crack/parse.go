package crack

import (
	"strconv"
	"strings"
)

func ParseTargets(targets []string) (results []*IpAddr) {
	for _, target := range targets {
		target = strings.TrimSpace(target)
		tmp := strings.Split(target, ":")
		if len(tmp) != 2 {
			continue
		}
		ip := tmp[0]
		tmp = strings.Split(tmp[1], "|")
		if len(tmp) == 2 { // ip列表中指定了端口对应的服务
			port, _ := strconv.Atoi(tmp[0])
			protocol := tmp[1]
			if SupportProtocols[protocol] {
				results = append(results, &IpAddr{
					Ip:       ip,
					Port:     port,
					Protocol: protocol,
				})
			}
		} else { // 通过端口查默认服务
			port, _ := strconv.Atoi(tmp[0])
			protocol, ok := PortNames[port]
			if ok && SupportProtocols[protocol] {
				results = append(results, &IpAddr{
					Ip:       ip,
					Port:     port,
					Protocol: protocol,
				})
			}
		}
	}

	return
}

func FilterModule(addrs []*IpAddr, module string) (results []*IpAddr) {
	if module == "all" {
		return addrs
	}
	for _, addr := range addrs {
		if addr.Protocol == module {
			results = append(results, addr)
		}
	}
	return results
}
