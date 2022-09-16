package plugins

import (
	"fmt"
	"time"

	"github.com/jlaffaye/ftp"
)

func FtpCrack(serv *Service) int {
	addr := fmt.Sprintf("%v:%v", serv.Ip, serv.Port)
	servConn, err := ftp.Dial(addr, ftp.DialWithTimeout(time.Duration(serv.Timeout)*time.Second))
	if err != nil {
		return CrackError
	}
	err = servConn.Login(serv.User, serv.Pass)
	if err != nil {
		return CrackFail
	}
	defer servConn.Logout() // nolint
	return CrackSuccess
}
