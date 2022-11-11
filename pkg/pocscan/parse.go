package pocscan

import (
	"fmt"
	"strings"
)

func ParseTargets(targets []string) (results []*Input, err error) {
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
		pocTags := strings.Split(tmp[1], ",")
		results = append(results, &Input{
			Target:  url,
			PocTags: pocTags,
		})
	}
	return
}
