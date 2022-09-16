package plugins

import (
	"strings"

	"github.com/niudaii/zpscan/pkg/crack/plugins/smb"
)

func SmbCrack(serv *Service) int {
	options := smb.Options{
		Host:        serv.Ip,
		Port:        serv.Port,
		User:        serv.User,
		Password:    serv.Pass,
		Domain:      "",
		Workstation: "",
		Timeout:     serv.Timeout,
	}
	session, err := smb.NewSession(options, false)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			return CrackError
		}
		return CrackFail
	}
	session.Close()
	if session.IsAuthenticated {
		return CrackSuccess
	}
	return CrackFail
}
