package plugins

import (
	"fmt"
	"strings"

	"github.com/niudaii/zpscan/pkg/crack/plugins/grdp"
)

func RdpCrack(serv *Service) (int, error) {
	addr := fmt.Sprintf("%v:%v", serv.Ip, serv.Port)
	err := grdp.Login(addr, "", serv.User, serv.Pass, serv.Timeout)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			return CrackError, err
		}
		return CrackFail, nil
	}
	return CrackSuccess, nil
}
