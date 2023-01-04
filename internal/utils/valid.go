package utils

import (
	"regexp"
)

var (
	reIp = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$|^\d+\.\d+\.\d+\.\d+/\d+$|^\d+\.\d+\.\d+.\d+-\d+$`)
)

func IsVaildIp(str string) bool {
	return reIp.Match([]byte(str))
}
