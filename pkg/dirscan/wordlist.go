package dirscan

import (
	"fmt"
	"strings"
)

func GenerateDomainDirs(domain string) (results []string) {
	results = append(results, generatePossibilities(domain)...)
	return
}

func GenerateIpDirs(ip string) (results []string) {
	for _, extension := range extensions {
		results = append(results, fmt.Sprintf("%v%v", ip, extension))
	}
	return
}

func generatePossibilities(domain string) (results []string) {
	split := strings.Split(domain, ".")
	results = append(results, split[0])
	for i := 0; i < len(split); i++ {
		for j := i; j < len(split); j++ {
			for _, extension := range extensions {
				result := strings.Join(split[i:j+1], ".") + extension
				results = append(results, result)
			}
		}
	}
	return
}
