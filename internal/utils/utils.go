package utils

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
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

func HasStr(datas []string, to string) bool {
	for _, data := range datas {
		if to == data {
			return true
		}
	}
	return false
}

func SuffixStr(datas []string, to string) (string, bool) {
	for _, data := range datas {
		if strings.HasSuffix(to, data) {
			return data, true
		}
	}
	return "", false
}

func HasInt(datas []int, to int) bool {
	for _, data := range datas {
		if to == data {
			return true
		}
	}
	return false
}
