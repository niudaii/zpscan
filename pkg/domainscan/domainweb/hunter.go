package domainweb

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/imroc/req/v3"
	"time"
)

type hunterRst struct {
	//Error   bool     `json:"error"`
	//Size    int      `json:"size"`
	//Results []string `json:"results"`
}

var (
	hunterApi = "https://hunter.qianxin.com/openApi/search"
)

func hunter(query, apiKey string) (hosts []string, err error) {
	query = fmt.Sprintf("domain=\"%v\"", query)
	qBase64 := base64.StdEncoding.EncodeToString([]byte(query))
	r := req.C().SetTimeout(15 * time.Second).R()
	r.SetQueryParams(map[string]string{
		"api-key": apiKey,
		"search":  qBase64,
		"page":    "1",
		"size":    "100",
		"is_web":  "3",
	})
	resp, err := r.Get(hunterApi)
	if err != nil {
		return
	}
	var res hunterRst
	err = json.Unmarshal(resp.Bytes(), &res)
	if err != nil {
		return
	}
	//hosts = res.Results
	return
}
