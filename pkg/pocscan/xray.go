package pocscan

import (
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/pocscan/cel"
	"github.com/niudaii/zpscan/pkg/pocscan/cel/proto"
	"github.com/niudaii/zpscan/pkg/pocscan/common"
	"github.com/niudaii/zpscan/pkg/pocscan/xray"
	"github.com/projectdiscovery/gologger"
	"net/url"
	"strings"
	"time"
)

func (r *Runner) RunXrayPoc(target string, pocTag string) (results []*common.Result) {
	var pocList []*xray.Poc
	for _, poc := range r.xrayPocs {
		// 判断 Name
		if strings.Contains(strings.ToLower(poc.Name), pocTag) {
			pocList = append(pocList, poc)
		}
	}
	if len(pocList) == 0 {
		gologger.Error().Msgf("load 0 xray pocs")
		return
	}
	gologger.Info().Msgf("load %v xray pocs", len(pocList))
	for _, poc := range pocList {
		res, err := r.ScanXray(target, poc)
		if err != nil {
			gologger.Error().Msgf("r.Scan() err, %v", err)
			continue
		}
		if res {
			result := &common.Result{
				Target:  target,
				PocTag:  pocTag,
				Source:  "xray",
				PocName: poc.Name,
			}
			gologger.Silent().Msgf("[%v] [%v] [%v] [%v]", time.Now().Format("2006-01-02 15:04:05"), result.Source, result.PocName, result.Level)
			results = append(results, result)
		}
	}

	return
}
func (r *Runner) ScanXray(target string, poc *xray.Poc) (result bool, err error) {
	// 对于协议是tcp或udp先不处理
	if poc.Transport == "tcp" || poc.Transport == "udp" {
		return
	}
	// init cel env map
	celController := &cel.CelController{}
	err = celController.InitCel(poc)
	if err != nil {
		return
	}
	// 需要request set中需要
	pReq := common.GetPReqByTarget(target)
	// 处理set
	err = celController.InitSet(poc, pReq)
	if err != nil {
		return
	}
	// rules
	for key, rule := range poc.Rules {
		rule.ReplaceSet(celController.ParamMap)
		// 根据原始请求 + rule 生成并发起新的请求 http
		var resp *proto.Response
		resp, err = r.DoRequest(target, &rule)
		if err != nil {
			return
		}
		celController.ParamMap["response"] = resp
		// 匹配search规则
		if rule.Output.Search != "" {
			celController.ParamMap = rule.ReplaceSearch(resp, celController.ParamMap)
		}
		// 执行表达式
		var out bool
		out, err = celController.Evaluate(rule.Expression)
		if err != nil {
			return
		}
		// 将out结果写到env map里 最后再次更新env后 执行XrayPoc 表达式来判断是否成功
		// 这里更新cel的函数将rule的name的函数定义进去
		// celController.ParamMap[key] = out
		celController.UpdateRule(key, out)
	}
	// rule都跑完后要更新env 将构建的rule函数构建进去
	celController.UpdateEnv()
	out, err := celController.Evaluate(poc.Expression)
	// 目前要求把失败的和成功都存储下来
	if out {
		result = true
	}
	return
}

func (r *Runner) DoRequest(target string, rule *xray.Rule) (prsp *proto.Response, err error) {
	parseUrl, err := url.Parse(target)
	if err != nil {
		return
	}
	TargetBaseUrl := parseUrl.Scheme + "://" + parseUrl.Host
	targetUrl := TargetBaseUrl + rule.Request.Path
	targetUrl = strings.ReplaceAll(targetUrl, " ", "%20")
	targetUrl = strings.ReplaceAll(targetUrl, "+", "%20")
	request := r.reqClient.R()
	request.SetBodyString(rule.Request.Body)
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
