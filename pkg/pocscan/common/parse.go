package common

import (
	"github.com/niudaii/zpscan/pkg/pocscan/cel/proto"
	"net/url"
	"strings"
)

func UrlToPUrl(url *url.URL) *proto.UrlType {
	nu := &proto.UrlType{}
	nu.Scheme = url.Scheme
	nu.Domain = url.Hostname()
	nu.Host = url.Host
	nu.Port = url.Port()
	nu.Path = url.EscapedPath()
	nu.Query = url.RawQuery
	nu.Fragment = url.Fragment
	return nu
}

func GetPReqByTarget(target string) *proto.Request {
	pReq := &proto.Request{}
	parseUrl, _ := url.Parse(target)
	pReq.Url = UrlToPUrl(parseUrl)
	return pReq
}

func UrlTypeToString(u *proto.UrlType) string {
	var buf strings.Builder
	if u.Scheme != "" {
		buf.WriteString(u.Scheme)
		buf.WriteByte(':')
	}
	if u.Scheme != "" || u.Host != "" {
		if u.Host != "" || u.Path != "" {
			buf.WriteString("//")
		}
		if h := u.Host; h != "" {
			buf.WriteString(u.Host)
		}
	}
	path := u.Path
	if path != "" && path[0] != '/' && u.Host != "" {
		buf.WriteByte('/')
	}
	if buf.Len() == 0 {
		if i := strings.IndexByte(path, ':'); i > -1 && strings.IndexByte(path[:i], '/') == -1 {
			buf.WriteString("./")
		}
	}
	buf.WriteString(path)

	if u.Query != "" {
		buf.WriteByte('?')
		buf.WriteString(u.Query)
	}
	if u.Fragment != "" {
		buf.WriteByte('#')
		buf.WriteString(u.Fragment)
	}
	return buf.String()
}
