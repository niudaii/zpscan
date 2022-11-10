package webscan

import (
	"fmt"
	"github.com/niudaii/zpscan/internal/utils"
	"strings"

	"github.com/imroc/req/v3"
	"github.com/projectdiscovery/gologger"
)

func (r *Runner) getFinger(resp *req.Response) (results []*FingerRule) {
	bodyString := resp.String()
	headerString := utils.GetHeaderString(resp)
	certString := utils.GetCert(resp)
	iconMap := map[string]string{}
	var toMatch string
	var rules string
	var flag1 bool
	var flag2 bool
	var flag3 int
	// 多个 FingerRules
	for _, fingerRule := range r.options.FingerRules {
		rules = ""
		flag1 = false
		// 单个 fingerRule 多个 finger
		for _, finger := range fingerRule.Fingers {
			flag3 = 0
			// 单个 finger 多个 rules
			for _, rule := range finger.Rules {
				flag2 = false
				if rule.Method == "keyword" {
					if rule.Location == "body" {
						toMatch = bodyString
					}
					if rule.Location == "header" {
						toMatch = headerString
					}
					if rule.Location == "cert" {
						toMatch = certString
					}
				} else if rule.Method == "iconhash" {
					if value, ok := iconMap[rule.Location]; ok {
						toMatch = value
					} else {
						toMatch = r.GetHash(resp.Request.URL.Scheme + "://" + resp.Request.URL.Host + rule.Location)
						iconMap[rule.Location] = toMatch
					}
				}
				if strings.Contains(toMatch, rule.Keyword) {
					flag2 = true
				}
				if flag2 {
					// 当前成立,为and继续循环,为or直接成立
					if finger.Type == "and" {
						flag3 += 1
						rules += fmt.Sprintf("%v %v %v | ", rule.Method, rule.Location, rule.Keyword)
					} else if finger.Type == "or" {
						flag1 = true
						rules = fmt.Sprintf("%v %v %v", rule.Method, rule.Location, rule.Keyword)
						break
					}
				} else {
					// 当前不成立,为and直接不成立
					if finger.Type == "and" {
						break
					}
				}
			}
			if flag3 == len(finger.Rules) {
				flag1 = true
			}
		}
		if flag1 {
			gologger.Debug().Msgf("%v => [%v] by [%v]", resp.Request.URL, fingerRule.Name, rules)
			results = append(results, fingerRule)
		}
	}
	return
}
