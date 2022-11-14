package plugins

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/microsoft/go-mssqldb"
)

func MssqlCrack(serv *Service) (int, error) {
	dataSourceName := fmt.Sprintf("sqlserver://%v:%v@%v:%v?encrypt=disable&dial+timeout=%v&connection+timeout=%v", serv.User, serv.Pass, serv.Ip, serv.Port, serv.Timeout, serv.Timeout)
	db, err := sql.Open("sqlserver", dataSourceName)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			return CrackError, err
		}
		return CrackFail, nil
	}
	db.SetConnMaxLifetime(time.Duration(serv.Timeout) * time.Second)
	db.SetConnMaxIdleTime(time.Duration(serv.Timeout) * time.Second)
	db.SetMaxIdleConns(0)
	defer db.Close()
	err = db.Ping()
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			return CrackError, err
		}
		return CrackFail, nil
	}
	return CrackSuccess, nil
}
