package nuclei

import (
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"gopkg.in/yaml.v2"
	"strings"
)

// LoadAllExp 加载全部exp
func LoadAllExp(dir string) (exps []*Template, err error) {
	var pathList []string
	pathList, err = utils.GetAllFile(dir)
	if err != nil {
		return
	}
	for _, path := range pathList {
		if !strings.HasSuffix(path, "-exp.yaml") {
			continue
		}
		var data []byte
		data, err = utils.ReadFile(path)
		if err != nil {
			return
		}
		template := &templates.Template{}
		if err = yaml.Unmarshal(data, template); err != nil {
			return
		}
		template.Path = path
		exps = append(exps, template)
	}
	return
}
