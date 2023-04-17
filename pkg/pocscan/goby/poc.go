package goby

import (
	"encoding/json"
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/pocscan/cel/proto"
	"io/ioutil"
	"strconv"
	"strings"
)

type Poc struct {
	Name           string        `json:"Name"`
	Description    string        `json:"Description"`
	Product        string        `json:"Product"`
	Homepage       string        `json:"Homepage"`
	DisclosureDate string        `json:"DisclosureDate"`
	Author         string        `json:"Author"`
	FofaQuery      string        `json:"FofaQuery"`
	GobyQuery      string        `json:"GobyQuery"`
	Level          string        `json:"Level"`
	Impact         string        `json:"Impact"`
	VulType        []interface{} `json:"VulType"`
	CVEIDs         []interface{} `json:"CVEIDs"`
	CNNVD          []interface{} `json:"CNNVD"`
	CNVD           []interface{} `json:"CNVD"`
	CVSSScore      string        `json:"CVSSScore"`
	Is0Day         bool          `json:"Is0day"`
	Recommendation string        `json:"Recommendation"`
	Translation    struct {
		CN struct {
			Name           string        `json:"Name"`
			Product        string        `json:"Product"`
			Description    string        `json:"Description"`
			Recommendation string        `json:"Recommendation"`
			Impact         string        `json:"Impact"`
			VulType        []interface{} `json:"VulType"`
			Tags           []interface{} `json:"Tags"`
		} `json:"CN"`
		EN struct {
			Name           string        `json:"Name"`
			Product        string        `json:"Product"`
			Description    string        `json:"Description"`
			Recommendation string        `json:"Recommendation"`
			Impact         string        `json:"Impact"`
			VulType        []interface{} `json:"VulType"`
			Tags           []interface{} `json:"Tags"`
		} `json:"EN"`
	} `json:"Translation"`
	References []string    `json:"References"`
	HasExp     bool        `json:"HasExp"`
	ExpParams  interface{} `json:"ExpParams"`
	ExpTips    struct {
		Type    string `json:"Type"`
		Content string `json:"Content"`
	} `json:"ExpTips"`
	ScanSteps      []interface{} `json:"ScanSteps"`
	ExploitSteps   interface{}   `json:"ExploitSteps"`
	Tags           interface{}   `json:"Tags"`
	AttackSurfaces struct {
		Application interface{} `json:"Application"`
		Support     interface{} `json:"Support"`
		Service     interface{} `json:"Service"`
		System      interface{} `json:"System"`
		Hardware    interface{} `json:"Hardware"`
	} `json:"AttackSurfaces"`
}

type Rule struct {
	Request struct {
		Data           string            `json:"data"`
		DataType       string            `json:"data_type"`
		FollowRedirect bool              `json:"follow_redirect"`
		Header         map[string]string `json:"header"`
		Method         string            `json:"method"`
		Uri            string            `json:"uri"`
	} `json:"Request"`
	ResponseTest struct {
		Checks    []Checks `json:"checks"`
		Operation string   `json:"operation"`
		Type      string   `json:"type"`
	} `json:"ResponseTest"`
	SetVariable []interface{} `json:"SetVariable"`
}

type Checks struct {
	Bz        string `json:"bz"`
	Operation string `json:"operation"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Variable  string `json:"variable"`
}

// LoadAllPoc 加载全部poc
func LoadAllPoc(pocDir string) (pocs []*Poc, err error) {
	var pocPathList []string
	pocPathList, err = utils.GetAllFile(pocDir)
	if err != nil {
		return
	}
	for _, pocPath := range pocPathList {
		if !strings.HasSuffix(pocPath, ".json") {
			continue
		}
		var poc Poc
		var bytes []byte
		bytes, err = ioutil.ReadFile(pocPath)
		if err != nil {
			return
		}
		err = json.Unmarshal(bytes, &poc)
		if err != nil {
			return
		}
		pocs = append(pocs, &poc)
	}
	return
}

// CheckResult checks
func (r *Rule) CheckResult(preq *proto.Response) bool {
	var result []bool
	var result1 bool
	for _, check := range r.ResponseTest.Checks {
		result1 = CheckOperation(check, preq)
		result = append(result, result1)
	}
	if r.ResponseTest.Operation == "AND" {
		for _, res := range result {
			if !res {
				return false
			}
		}
		return true
	} else if r.ResponseTest.Operation == "OR" {
		for _, res := range result {
			if res {
				return true
			}
		}
	}
	return false
}

// CheckOperation operation
func CheckOperation(check Checks, preq *proto.Response) bool {
	switch {
	case strings.EqualFold(check.Operation, "contains"):
		{
			if check.Variable == "$body" {
				if strings.Contains(string(preq.Body), check.Value) {
					return true
				}
			} else if check.Variable == "$head" {
				for _, header := range preq.Headers {
					if strings.Contains(header, check.Value) {
						return true
					}
				}
			} else if check.Variable == "$code" {
				if strings.Contains(strconv.Itoa(int(preq.Status)), check.Value) {
					return true
				}
			}
		}
	case strings.EqualFold(check.Operation, "not contains"):
		{
			if check.Variable == "$body" {
				if !(strings.Contains(string(preq.Body), check.Value)) {
					return true
				}
			} else if check.Variable == "$head" {
				for _, header := range preq.Headers {
					if !(strings.Contains(header, check.Value)) {
						return true
					}
				}
			} else if check.Variable == "$code" {
				if !(strings.Contains(strconv.Itoa(int(preq.Status)), check.Value)) {
					return true
				}
			}
		}
	case strings.EqualFold(check.Operation, "start_with"):
		{
			if check.Variable == "$body" {
				if strings.HasPrefix(string(preq.Body), check.Value) {
					return true
				}
			} else if check.Variable == "$head" {
				for _, header := range preq.Headers {
					if strings.HasPrefix(header, check.Value) {
						return true
					}
				}
			} else if check.Variable == "$code" {
				if strings.HasPrefix(strconv.Itoa(int(preq.Status)), check.Value) {
					return true
				}
			}
		}
	case strings.EqualFold(check.Operation, "end_with"):
		{
			if check.Variable == "$body" {
				if strings.HasSuffix(string(preq.Body), check.Value) {
					return true
				}
			} else if check.Variable == "$head" {
				for _, header := range preq.Headers {
					if strings.HasSuffix(header, check.Value) {
						return true
					}
				}
			} else if check.Variable == "$code" {
				if strings.HasSuffix(strconv.Itoa(int(preq.Status)), check.Value) {
					return true
				}
			}
		}
	case strings.EqualFold(check.Operation, "=="):
		{
			if check.Variable == "$body" {
				if check.Value == string(preq.Body) {
					return true
				}
			} else if check.Variable == "$head" {
				for _, header := range preq.Headers {
					if check.Value == header {
						return true
					}
				}
			} else if check.Variable == "$code" {
				if check.Value == strconv.Itoa(int(preq.Status)) {
					return true
				}
			}
		}
	case strings.EqualFold(check.Operation, "!="):
		{
			if check.Variable == "$body" {
				if check.Value != string(preq.Body) {
					return true
				}
			} else if check.Variable == "$head" {
				for _, header := range preq.Headers {
					if check.Value != header {
						return true
					}
				}
			} else if check.Variable == "$code" {
				if check.Value != strconv.Itoa(int(preq.Status)) {
					return true
				}
			}
		}
	case strings.EqualFold(check.Operation, ">"):
		{
			if check.Variable == "$body" {
				if check.Value > string(preq.Body) {
					return true
				}
			} else if check.Variable == "$head" {
				for _, header := range preq.Headers {
					if check.Value > header {
						return true
					}
				}
			} else if check.Variable == "$code" {
				if check.Value > strconv.Itoa(int(preq.Status)) {
					return true
				}
			}
		}
	case strings.EqualFold(check.Operation, "<"):
		{
			if check.Variable == "$body" {
				if check.Value < string(preq.Body) {
					return true
				}
			} else if check.Variable == "$head" {
				for _, header := range preq.Headers {
					if check.Value < header {
						return true
					}
				}
			} else if check.Variable == "$code" {
				if check.Value < strconv.Itoa(int(preq.Status)) {
					return true
				}
			}
		}
	case strings.EqualFold(check.Operation, ">="):
		{
			if check.Variable == "$body" {
				if check.Value >= string(preq.Body) {
					return true
				}
			} else if check.Variable == "$head" {
				for _, header := range preq.Headers {
					if check.Value >= header {
						return true
					}
				}
			} else if check.Variable == "$code" {
				if check.Value >= strconv.Itoa(int(preq.Status)) {
					return true
				}
			}
		}
	case strings.EqualFold(check.Operation, "<="):
		{
			if check.Variable == "$body" {
				if check.Value <= string(preq.Body) {
					return true
				}
			} else if check.Variable == "$head" {
				for _, header := range preq.Headers {
					if check.Value <= header {
						return true
					}
				}
			} else if check.Variable == "$code" {
				if check.Value <= strconv.Itoa(int(preq.Status)) {
					return true
				}
			}
		}
	default:
		return false
	}
	return false
}
