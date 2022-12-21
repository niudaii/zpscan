package pocscan

import (
	"fmt"
	"strings"
)

func ParsePocInput(targets []string) (results []*PocInput, err error) {
	for _, target := range targets {
		if !strings.Contains(target, "|") {
			err = fmt.Errorf("input 必须指定 pocTags，example: -i http://127.0.0.1:9200|elasticsearch")
			return
		}
		target = strings.TrimSpace(target)
		tmp := strings.Split(target, "|")
		if len(tmp) != 2 {
			continue
		}
		url := tmp[0]
		PocTags := strings.Split(tmp[1], ",")
		results = append(results, &PocInput{
			Target:  url,
			PocTags: PocTags,
		})
	}
	return
}

func ParseExpInput(targets []string, payload string) (results []*ExpInput, err error) {
	for _, target := range targets {
		if !strings.Contains(target, "|") {
			err = fmt.Errorf("input 必须指定 pocTags，example: -i http://127.0.0.1:9200|CVE-2015-1427")
			return
		}
		target = strings.TrimSpace(target)
		tmp := strings.Split(target, "|")
		if len(tmp) != 2 {
			continue
		}
		url := tmp[0]
		pocName := tmp[1]
		results = append(results, &ExpInput{
			Target:  url,
			PocName: pocName,
			Payload: payload,
		})
	}
	return
}
