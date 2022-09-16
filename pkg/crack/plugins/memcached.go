package plugins

import (
	"fmt"
	"net"
	"strings"
	"time"
)

func MemcachedCrack(serv *Service) int {
	// 未授权
	return MemcachedUnAuth(serv)
}

func MemcachedUnAuth(serv *Service) int {
	addr := fmt.Sprintf("%v:%v", serv.Ip, serv.Port)
	conn, err := net.DialTimeout("tcp", addr, time.Duration(serv.Timeout)*time.Second)
	if err != nil {
		return CrackError
	}
	err = conn.SetDeadline(time.Now().Add(time.Duration(serv.Timeout) * time.Second))
	if err != nil {
		return CrackError
	}
	defer conn.Close()
	_, err = conn.Write([]byte("stats\n"))
	if err == nil {
		rev := make([]byte, 1024)
		n, err := conn.Read(rev)
		if err == nil {
			if strings.Contains(string(rev[:n]), "STAT") {
				return CrackSuccess
			}
		}
	}
	return CrackError
}
