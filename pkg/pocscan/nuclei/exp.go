package nuclei

import (
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"strings"
)

// LoadAllExp 加载全部exp
func LoadAllExp(pocDir string) (exps []*Template, err error) {
	var pocPathList []string
	pocPathList, err = utils.GetAllFile(pocDir)
	if err != nil {
		return
	}
	for _, pocPath := range pocPathList {
		if !strings.HasSuffix(pocPath, "-exp.yaml") {
			continue
		}
		var exp *Template
		exp, err = templates.Parse(pocPath, nil, ExecuterOptions)
		if err != nil {
			gologger.Error().Msgf("ParsePocFile() %v err, %v", pocPath, err)
			continue
		}
		exps = append(exps, exp)
	}
	return
}
