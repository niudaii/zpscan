package plugins

import (
	"strings"

	"github.com/niudaii/zpscan/pkg/crack/plugins/smb"
)

func SmbCrack(serv *Service) (int, error) {
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
			return CrackError, err
		}
		return CrackFail, nil
	}
	session.Close()
	if session.IsAuthenticated {
		return CrackSuccess, nil
	}
	return CrackFail, nil
}
