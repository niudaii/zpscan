package pocscan

import (
	"github.com/niudaii/zpscan/pkg/pocscan/goby"
	"github.com/niudaii/zpscan/pkg/pocscan/nuclei"
	"github.com/niudaii/zpscan/pkg/pocscan/xray"
	"testing"
)

type Input struct {
	Url     string
	PocTags []string
}

func TestRun(t *testing.T) {
	tests := map[string]Input{
		"success": {
			Url:     "http://127.0.0.1:9200",
			PocTags: []string{"elasticsearch"},
		},
		//"fail": {
		//	Url:     "http://106.75.26.138:8000/",
		//	PocTags: []string{"11"},
		//},
	}
	options := Options{
		Proxy:   "http://127.0.0.1:8080",
		Timeout: 10,
	}
	pocDir := "/Users/root/go/src/zpscan/resource/pocscan/goby"
	gobyPocs, err := goby.LoadAllPoc(pocDir)
	if err != nil {
		t.Error(err)
	}
	t.Log("gobyPocs", len(gobyPocs))
	pocDir = "/Users/root/go/src/zpscan/resource/pocscan/xray"
	xrayPocs, err := xray.LoadAllPoc(pocDir)
	if err != nil {
		t.Error(err)
	}
	t.Log("xrayPocs", len(xrayPocs))
	pocDir = "/Users/root/go/src/zpscan/resource/pocscan/nuclei"
	err = nuclei.InitNuclei(pocDir, 10, options.Timeout, options.Proxy)
	if err != nil {
		t.Error(err)
	}
	nucleiPcs, err := nuclei.LoadAllPoc(pocDir)
	if err != nil {
		t.Error(err)
	}
	t.Log("nucleiPcs", len(nucleiPcs))
	r, err := NewRunner(&options, gobyPocs, xrayPocs, nucleiPcs)
	if err != nil {
		t.Error(err)
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r.Pocscan(tc.Url, tc.PocTags)
		})
	}
}
