package pocscan

import (
	"github.com/niudaii/zpscan/pkg/pocscan/goby"
	"github.com/niudaii/zpscan/pkg/pocscan/nuclei"
	"github.com/niudaii/zpscan/pkg/pocscan/xray"
	"testing"
)

func TestRun(t *testing.T) {
	tests := map[string]*PocInput{
		"success": {
			Target:  "http://127.0.0.1:9200",
			PocTags: []string{"elasticsearch"},
		},
		"fail": {
			Target:  "http://127.0.0.1:8092",
			PocTags: []string{"11"},
		},
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
	nucleiPcs, err := nuclei.LoadAllPoc(pocDir)
	if err != nil {
		t.Error(err)
	}
	t.Log("nucleiPcs", len(nucleiPcs))
	var nucleiPocs []*nuclei.Template
	r, err := NewRunner(&options, gobyPocs, xrayPocs, nucleiPocs)
	if err != nil {
		t.Error(err)
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r.Pocscan(tc)
		})
	}
}
