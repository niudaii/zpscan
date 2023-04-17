package nuclei

import (
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"strings"
)

// LoadAllExp 加载全部exp
func LoadAllExp(dir string) (exps []*Template, err error) {
	err = InitExecuterOptions(dir)
	if err != nil {
		return
	}
	var pathList []string
	pathList, err = utils.GetAllFile(dir)
	if err != nil {
		return
	}
	for _, path := range pathList {
		if !strings.HasSuffix(path, "-exp.yaml") {
			continue
		}
		var template *Template
		template, err = templates.Parse(path, nil, ExecuterOptions)
		if err != nil {
			return
		}
		template.Path = path
		exps = append(exps, template)
	}
	return
}
