package utils

import (
	"github.com/imroc/req/v3"
	"strings"
	"time"
)

func NewReqClient(proxy string, timeout int, headers []string) *req.Client {
	reqClient := req.C()
	reqClient.GetTLSClientConfig().InsecureSkipVerify = true
	reqClient.SetCommonHeaders(map[string]string{
		"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36",
	})
	reqClient.SetRedirectPolicy(req.AlwaysCopyHeaderRedirectPolicy("Cookie"))
	if proxy != "" {
		reqClient.SetProxyURL(proxy)
	}
	var key, value string
	for _, header := range headers {
		tokens := strings.SplitN(header, ":", 2)
		if len(tokens) < 2 {
			continue
		}
		key = strings.TrimSpace(tokens[0])
		value = strings.TrimSpace(tokens[1])
		reqClient.SetCommonHeader(key, value)
	}
	reqClient.SetTimeout(time.Duration(timeout) * time.Second)
	return reqClient
}

func GetHeaderMap(resp *req.Response) (headerMap map[string]string) {
	headerMap = map[string]string{}
	for k := range resp.Header {
		if k != "Set-Cookie" {
			headerMap[k] = resp.Header.Get(k)
		}
	}
	for _, ck := range resp.Cookies() {
		headerMap["Set-Cookie"] += ck.String() + ";"
	}
	return
}

func GetHeaderString(resp *req.Response) (headerString string) {
	headerMap := map[string]string{}
	for k := range resp.Header {
		if k != "Set-Cookie" {
			headerMap[k] = resp.Header.Get(k)
		}
	}
	for _, ck := range resp.Cookies() {
		headerMap["Set-Cookie"] += ck.String() + ";"
	}
	for k, v := range headerMap {
		headerString += k + ": " + v + "\n"
	}
	return headerString
}

func GetCert(resp *req.Response) (cert string) {
	if resp.TLS != nil {
		cert = resp.TLS.PeerCertificates[0].Subject.String()
	}
	return cert
}
