package plugins

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis"
)

func RedisCrack(serv *Service) int {
	addr := fmt.Sprintf("%v:%v", serv.Ip, serv.Port)
	opt := redis.Options{
		Addr:        addr,
		Password:    serv.Pass,
		DB:          0,
		DialTimeout: time.Duration(serv.Timeout) * time.Second,
	}
	client := redis.NewClient(&opt)
	defer client.Close()
	_, err := client.Ping().Result()
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			return CrackError
		}
		return CrackFail
	}
	return CrackSuccess
}
