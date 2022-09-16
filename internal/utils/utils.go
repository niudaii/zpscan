package utils

import (
	"crypto/md5"
	"encoding/hex"
)

func RemoveDuplicate(list []string) []string {
	var set []string
	hashSet := make(map[string]struct{})
	for _, v := range list {
		hashSet[v] = struct{}{}
	}
	for k := range hashSet {
		// 去除空字符串
		if k == "" {
			continue
		}
		set = append(set, k)
	}
	return set
}

func Md5(s string) string {
	m := md5.New()
	m.Write([]byte(s))
	return hex.EncodeToString(m.Sum(nil))
}

func IsExclude(m []int, value int) bool {
	for _, v := range m {
		if v == value {
			return true
		}
	}
	return false
}
