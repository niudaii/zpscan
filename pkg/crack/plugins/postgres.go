package plugins

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

func PostgresCrack(serv *Service) int {
	dataSourceName := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v&connect_timeout=%v", serv.User, serv.Pass, serv.Ip, serv.Port, "", "disable", serv.Timeout)
	db, err := sql.Open("postgres", dataSourceName)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			return CrackError
		}
		return CrackFail
	}
	db.SetConnMaxLifetime(time.Duration(serv.Timeout) * time.Second)
	defer db.Close()
	err = db.Ping()
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			return CrackError
		}
		return CrackFail
	}
	return CrackSuccess
}
