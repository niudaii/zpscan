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
	for _, domain := range subdomains {
		results = append(results, CheckUrl(domain, timeout, threads, proxy)...)
	}
	return
}

func CheckUrl(host string, timeout, threads int, proxy string) (results []string) {
	ports, err := utils.ParsePortsList(utils.Webport)
	if err != nil {
		return
	}
	for port := range ports {
		results = append(results, fmt.Sprintf("%v:%v", host, port))
	}
	results = webscan.CheckAlive(results, timeout, threads, proxy)
	return results
}
