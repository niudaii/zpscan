package pocscan

import (
	"encoding/json"
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/pocscan/cel/proto"
	"github.com/niudaii/zpscan/pkg/pocscan/common"
	"github.com/niudaii/zpscan/pkg/pocscan/goby"
	"github.com/projectdiscovery/gologger"
	"net/url"
	"strings"
	"time"
)

// RunGobyPoc 启动
func (r *Runner) RunGobyPoc(target string, pocTag string) (results []*common.Result) {
	var pocList []*goby.Poc
	for _, poc := range r.gobyPocs {
		// 判断 Name
		if strings.Contains(strings.ToLower(poc.Name), pocTag) {
			pocList = append(pocList, poc)
		}
	}
	if len(pocList) == 0 {
		gologger.Error().Msgf("load 0 goby pocs")
		return
	}
	gologger.Info().Msgf("load %v goby pocs", len(pocList))
	for _, poc := range pocList {
		gologger.Debug().Msgf("加载POC: %v", poc.Name)
		res, err := r.ScanGoby(target, poc)
		if err != nil {
			gologger.Error().Msgf("r.Scan() err, %v", err)
			continue
		}
		if res {
			result := &common.Result{
				Target:  target,
				PocTag:  pocTag,
				Source:  "goby",
				Level:   poc.Level,
				PocName: poc.Name,
			}
			gologger.Silent().Msgf("[%v] [%v] [%v] [%v]", time.Now().Format("2006-01-02 15:04:05"), result.Source, result.PocName, result.Level)
			results = append(results, result)
		}
	}

	return
}

// ScanGoby 扫描
func (r *Runner) ScanGoby(target string, poc *goby.Poc) (result bool, err error) {
	var scanOperation string
	var output []bool
	for _, step := range poc.ScanSteps {
		if step == "AND" {
			scanOperation = "AND"
			continue
		} else if step == "OR" {
			scanOperation = "OR"
			continue
		}
		// 解析 rule
		var bytes []byte
		bytes, err = json.Marshal(step)
		if err != nil {
			return
		}
		var rule goby.Rule
		err = json.Unmarshal(bytes, &rule)
		if err != nil {
			return
		}
		// 请求
		var resp *proto.Response
		resp, err = r.DoGobyRequest(target, &rule)
		if err != nil {
			return
		}
		out := rule.CheckResult(resp)
		output = append(output, out)
	}

	if scanOperation == "AND" {
		flag := true
		for _, out := range output {
			if !out {
				flag = false
				break
			}
		}
		if flag {
			result = true
		}
	} else if scanOperation == "OR" {
		flag := false
		for _, out := range output {
			if out {
				flag = true
				break
			}
		}
		if flag {
			result = true
		}
	}
	return
}

// DoGobyRequest 请求
func (r *Runner) DoGobyRequest(target string, rule *goby.Rule) (prsp *proto.Response, err error) {
	parseUrl, err := url.Parse(target)
	if err != nil {
		return
	}
	TargetBaseUrl := parseUrl.Scheme + "://" + parseUrl.Host
	targetUrl := TargetBaseUrl + rule.Request.Uri
	targetUrl = strings.ReplaceAll(targetUrl, " ", "%20")
	targetUrl = strings.ReplaceAll(targetUrl, "+", "%20")
	request := r.reqClient.R()
	request.SetBodyString(rule.Request.Data)
	resp, err := request.Send(rule.Request.Method, targetUrl)
	if err != nil {
		return
	}
	prsp = &proto.Response{
		Url:         common.UrlToPUrl(parseUrl),
		Status:      int32(resp.StatusCode),
		Headers:     utils.GetHeaderMap(resp),
		ContentType: resp.Header.Get("Content-Type"),
		Body:        resp.Bytes(),
	}
	return
}
