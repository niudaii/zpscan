package xray

import (
	"fmt"
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/pocscan/cel/proto"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"regexp"
	"strings"
)

type RuleRequest struct {
	Cache           bool              `yaml:"cache"`
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	FollowRedirects bool              `yaml:"follow_redirects"`
	Content         string            `yaml:"content"`
	ReadTimeout     string            `yaml:"read_timeout"`
	ConnectionID    string            `yaml:"connection_id"`
}

type Output struct {
	Search string `yaml:"search"`
	Home   string `yaml:"home"`
}
type Rule struct {
	Request    RuleRequest `yaml:"request"`
	Expression string      `yaml:"expression"`
	Output     Output      `yaml:"output"`
}

type Detail struct {
	Author      string   `yaml:"author"`
	Links       []string `yaml:"links"`
	Description string   `yaml:"description"`
}

type Poc struct {
	Name       string            `yaml:"name"`
	Transport  string            `yaml:"transport"`
	Set        yaml.MapSlice     `yaml:"set"`
	Rules      map[string]Rule   `json:"rules"`
	Groups     map[string][]Rule `json:"groups"`
	Expression string            `yaml:"expression"`
	Detail     Detail            `yaml:"detail"`
}

func LoadAllPoc(pocDir string) (pocs []*Poc, err error) {
	var pocPathList []string
	pocPathList, err = utils.GetAllFile(pocDir)
	if err != nil {
		return
	}
	for _, pocPath := range pocPathList {
		if !strings.HasSuffix(pocPath, ".yml") {
			continue
		}
		var poc Poc
		var bytes []byte
		bytes, err = ioutil.ReadFile(pocPath)
		if err != nil {
			return
		}
		err = yaml.Unmarshal(bytes, &poc)
		if err != nil {
			return
		}
		pocs = append(pocs, &poc)
	}
	return
}

func (rule *Rule) ReplaceSet(varMap map[string]interface{}) {
	for setKey, setValue := range varMap {
		// 过滤掉 map
		_, isMap := setValue.(map[string]string)
		if isMap {
			continue
		}
		value := fmt.Sprintf("%v", setValue)
		// 替换请求头中的 自定义字段
		for headerKey, headerValue := range rule.Request.Headers {
			rule.Request.Headers[headerKey] = strings.ReplaceAll(headerValue, "{{"+setKey+"}}", value)
		}
		// 替换请求路径中的 自定义字段
		rule.Request.Path = strings.ReplaceAll(strings.TrimSpace(rule.Request.Path), "{{"+setKey+"}}", value)
		// 替换body的 自定义字段
		rule.Request.Body = strings.ReplaceAll(strings.TrimSpace(rule.Request.Body), "{{"+setKey+"}}", value)
	}
}

// ReplaceSearch search
func (rule *Rule) ReplaceSearch(resp *proto.Response, varMap map[string]interface{}) map[string]interface{} {
	result := doSearch(strings.TrimSpace(rule.Output.Search), string(resp.Body))
	if len(result) > 0 { // 正则匹配成功
		for k, v := range result {
			varMap[k] = v
		}
	}
	return varMap
}

// doSearch 实现 search
func doSearch(re string, body string) map[string]string {
	r, err := regexp.Compile(re)
	if err != nil {
		return nil
	}
	result := r.FindStringSubmatch(body)
	names := r.SubexpNames()
	if len(result) > 1 && len(names) > 1 {
		paramsMap := make(map[string]string)
		for i, name := range names {
			if i > 0 && i <= len(result) {
				paramsMap[name] = result[i]
			}
		}
		return paramsMap
	}
	return nil
}
