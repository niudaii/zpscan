package domainweb

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/imroc/req/v3"
)

type rst struct {
	Error   bool     `json:"error"`
	Size    int      `json:"size"`
	Results []string `json:"results"`
}

var (
	url = "https://fofa.info/api/v1/search/all"
)

func fofa(query, fofaEmail, fofaKey string) (hosts []string, err error) {
	query = fmt.Sprintf("domain=\"%v\"", query)
	qBase64 := base64.StdEncoding.EncodeToString([]byte(query))
	r := req.C().SetTimeout(15 * time.Second).R()
	r.SetQueryParams(map[string]string{
		"email":   fofaEmail,
		"key":     fofaKey,
		"qbase64": qBase64,
		"page":    "1",
		"size":    "10000",
		"fields":  "host",
	})
	resp, err := r.Get(url)
	if err != nil {
		return
	}
	var res rst
	err = json.Unmarshal(resp.Bytes(), &res)
	if err != nil {
		return
	}
	hosts = res.Results
	return
}
