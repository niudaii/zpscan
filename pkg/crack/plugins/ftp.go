package plugins

import (
	"fmt"
	"time"

	"github.com/jlaffaye/ftp"
)

func FtpCrack(serv *Service) (int, error) {
	addr := fmt.Sprintf("%v:%v", serv.Ip, serv.Port)
	servConn, err := ftp.Dial(addr, ftp.DialWithTimeout(time.Duration(serv.Timeout)*time.Second))
	if err != nil {
		return CrackError, err
	}
	err = servConn.Login(serv.User, serv.Pass)
	if err != nil {
		return CrackFail, nil
	}
	defer servConn.Logout() // nolint
	return CrackSuccess, nil
}
