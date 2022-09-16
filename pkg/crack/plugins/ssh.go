package plugins

import (
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func SshCrack(serv *Service) int {
	config := &ssh.ClientConfig{
		User: serv.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(serv.Pass),
		},
		Timeout: time.Duration(serv.Timeout) * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", serv.Ip, serv.Port), config)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			return CrackError
		}
		return CrackFail
	}
	defer client.Close()
	session, err := client.NewSession()
	errRet := session.Run("echo zp857")
	if err != nil || errRet != nil {
		return CrackFail
	}
	defer session.Close()
	return CrackSuccess
}
