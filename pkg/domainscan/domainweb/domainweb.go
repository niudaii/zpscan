package domainweb

import (
	"fmt"
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/webscan"
)

//func Run(domain, fofaEmail, fofaKey string) (results []string, err error) {
//	fofaRes, err := fofa(domain, fofaEmail, fofaKey)
//	if err != nil {
//		return
//	}
//	results = append(results, fofaRes...)
//	return
//}

func Run(subdomains []string, timeout, threads int, proxy string) (results []string) {
	ports, err := utils.ParsePortsList(utils.Webport)
	if err != nil {
		return
	}
	var urls []string
	for _, subdomain := range subdomains {
		for port := range ports {
			urls = append(urls, fmt.Sprintf("%v:%v", subdomain, port))
		}
	}
	results = webscan.CheckAlive(urls, timeout, threads, proxy)
	return
}
