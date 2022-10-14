package webscan

import (
	"github.com/projectdiscovery/gologger"
	"regexp"
	"strings"

	"github.com/imroc/req/v3"
)

var (
	/*
		http://42.200.74.172
		<head>
			<meta http-equiv="refresh" content="1;URL='/admin'"/>
		</head>

		http://vip.wasu.com
		<!--
		<meta http-equiv="refresh" content="0.1;url=https://www.wasu.cn/">
		-->

		http://144.123.42.59:7077
		<head>
		<meta http-equiv=refresh content=0;url=index.jsp>
		</head>
	*/
	reg1 = regexp.MustCompile(`(?i)<meta.*?http-equiv=.*?refresh.*?url=(.*?)/?>`)
	/*
		https://183.235.236.180:4433
		<script type="text/javascript">
			location.href = "./ui/";
		</script>
	*/
	reg2 = regexp.MustCompile(`(?i)location\.href.*?=.*?"(.*?)"`)
)

func Jsjump(resp *req.Response) (jumpurl string) {
	res := regexJsjump(resp)
	gologger.Debug().Msgf("regexJsjump(), %v", res)
	if res != "" {
		res = strings.TrimSpace(res)
		res = strings.ReplaceAll(res, "\"", "")
		res = strings.ReplaceAll(res, "'", "")
		res = strings.ReplaceAll(res, "./", "/")
		var baseUrl string
		if strings.HasPrefix(res, "http") {
			jumpurl = res
		} else if strings.HasPrefix(res, "/") {
			// 前缀存在 / 时获取重定向之前的请求url
			baseUrl = resp.Request.URL.Scheme + "://" + resp.Request.URL.Host
			jumpurl = baseUrl + res
		} else {
			// 前缀不存在 / 时获取重定向之后的请求url
			baseUrl = resp.Response.Request.URL.String()
			if !strings.HasSuffix(baseUrl, "/") {
				baseUrl = baseUrl + "/"
			}
			jumpurl = baseUrl + res
		}
	}
	return jumpurl
}

func regexJsjump(resp *req.Response) string {
	matches := reg1.FindAllStringSubmatch(resp.String(), -1)
	if len(matches) > 0 {
		// 去除注释的情况
		if !strings.Contains(resp.String(), "<!--\r\n"+matches[0][0]) {
			return matches[0][1]
		}
	}
	if len(resp.String()) < 400 {
		matches = reg2.FindAllStringSubmatch(resp.String(), -1)
		if len(matches) > 0 {
			return matches[0][1]
		}
	}
	return ""
}
