package plugins

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func MysqlCrack(serv *Service) (int, error) {
	dataSourceName := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?charset=utf8&timeout=%v&readTimeout=%v", serv.User, serv.Pass, serv.Ip, serv.Port, "", time.Duration(serv.Timeout)*time.Second, time.Duration(serv.Timeout)*time.Second)
	db, err := sql.Open("mysql", dataSourceName)
	if err != nil {
		return CrackError, err
	}
	db.SetConnMaxLifetime(time.Duration(serv.Timeout) * time.Second)
	db.SetConnMaxIdleTime(time.Duration(serv.Timeout) * time.Second)
	db.SetMaxIdleConns(0)
	defer db.Close()
	err = db.Ping()
	if err != nil {
		if strings.Contains(err.Error(), "1045") {
			return CrackFail, nil
		}
		return CrackError, err
	}
	return CrackSuccess, nil
}
