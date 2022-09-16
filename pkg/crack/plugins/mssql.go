package plugins

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/denisenkom/go-mssqldb"
)

func MssqlCrack(serv *Service) int {
	dataSourceName := fmt.Sprintf("sqlserver://%v:%v@%v:%v?encrypt=disable&dial+timeout=%v&connection+timeout=%v", serv.User, serv.Pass, serv.Ip, serv.Port, serv.Timeout, serv.Timeout)
	db, err := sql.Open("sqlserver", dataSourceName)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			return CrackError
		}
		return CrackFail
	}
	db.SetConnMaxLifetime(time.Duration(serv.Timeout) * time.Second)
	db.SetConnMaxIdleTime(time.Duration(serv.Timeout) * time.Second)
	db.SetMaxIdleConns(0)
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
