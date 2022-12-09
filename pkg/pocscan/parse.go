package pocscan

import (
	"fmt"
	"github.com/niudaii/zpscan/pkg/pocscan/nuclei"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
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
			err = fmt.Errorf("input 必须指定 pocTags，example: -i http://127.0.0.1:9200|elasticsearch")
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

func InitNucleiPoc(dir, proxy string, timeout int) (pocs []*nuclei.Poc, engine *core.Engine, err error) {
	err = nuclei.InitExecuterOptions(dir)
	if err != nil {
		return
	}
	engine = nuclei.InitEngine(timeout, proxy)
	pocs, err = nuclei.LoadAllPoc(dir)
	if err != nil {
		return
	}
	//engine = nuclei.InitEngine(timeout, proxy) // bug 会检测失败
	return
}

func InitNucleiExp(dir, proxy string, timeout int) (exps []*nuclei.Exp, engine *core.Engine, err error) {
	err = nuclei.InitExecuterOptions(dir)
	if err != nil {
		return
	}
	engine = nuclei.InitEngine(timeout, proxy)
	exps, err = nuclei.LoadAllExp(dir)
	if err != nil {
		return
	}
	//engine = nuclei.InitEngine(timeout, proxy) // bug 会检测失败
	return
}
