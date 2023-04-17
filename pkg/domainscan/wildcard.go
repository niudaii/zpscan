package domainscan

import (
	"net"

	uuid "github.com/satori/go.uuid"
)

func CheckWildcard(domain string) (ok bool) {
	for i := 0; i < 2; i++ {
		_, err := net.LookupHost(uuid.NewV4().String() + "." + domain)
		if err == nil {
			return true
		}
	}
	return false
}
