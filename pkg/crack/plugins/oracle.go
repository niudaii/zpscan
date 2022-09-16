package plugins

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	go_ora "github.com/sijms/go-ora/v2"

	_ "github.com/sijms/go-ora/v2"
)

var services = []string{
	"orcl",
	"xe",
	"oracle",
}

func OracleCrack(serv *Service) (int, error) {
	for _, service := range services {
		conn, err := Conn(serv, service)
		if err != nil {
			if strings.Contains(err.Error(), "timeout") {
				return CrackError, err
			}
		}
		if conn {
			return CrackSuccess, nil
		}
	}
	return CrackFail, nil
}

func Conn(serv *Service, service string) (conn bool, err error) {
	urlOptions := map[string]string{
		"CONNECTION TIMEOUT": fmt.Sprintf("%v", serv.Timeout),
	}
	dataSourceName := go_ora.BuildUrl(serv.Ip, serv.Port, service, serv.User, serv.Pass, urlOptions)
	db, err := sql.Open("oracle", dataSourceName)
	if err != nil {
		return
	}
	db.SetConnMaxLifetime(time.Duration(serv.Timeout) * time.Second)
	db.SetConnMaxIdleTime(time.Duration(serv.Timeout) * time.Second)
	db.SetMaxIdleConns(0)
	err = db.Ping()
	defer db.Close()
	if err == nil {
		conn = true
	}
	return
}
