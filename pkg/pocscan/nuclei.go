package pocscan

import (
	"encoding/base64"
	"fmt"
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/pocscan/common"
	"github.com/niudaii/zpscan/pkg/pocscan/nuclei"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"strings"
	"time"
)

// RunNucleiPoc 启动
func (r *Runner) RunNucleiPoc(target string, keyword string) (results []*common.Result) {
	var pocList []*nuclei.Template
	for _, tmpPoc := range r.nucleiTemplates {
		// 判断 ID 和 tags
		if strings.Contains(strings.ToLower(tmpPoc.ID), keyword) || utils.HasStr(tmpPoc.Info.Tags.ToSlice(), keyword) {
			var poc *templates.Template
			poc, err := templates.Parse(tmpPoc.Path, nil, nuclei.ExecuterOptions)
			if err != nil {
				fmt.Println(err)
				continue
			}
			pocList = append(pocList, poc)
		}
	}
	if len(pocList) == 0 {
		gologger.Error().Msgf("load 0 nuclei pocs")
		return
	}
	gologger.Info().Msgf("load %v nuclei pocs", len(pocList))
	var err error
	results, err = r.NucleiPoc(target, pocList)
	if err != nil {
		gologger.Error().Msgf("NucleiPoc() err, %v", err)
		return
	}

	return
}

// RunNucleiExp 启动
func (r *Runner) RunNucleiExp(target, pocName, payload string) (results []*common.Result) {
	var pocList []*nuclei.Template
	for _, tmpPoc := range r.nucleiTemplates {
		var poc *templates.Template
		poc, err := templates.Parse(tmpPoc.Path, nil, nuclei.ExecuterOptions)
		if err != nil {
			fmt.Println(err)
			continue
		}
		if poc.ID == pocName+"-exp" {
			pocList = append(pocList, poc)
		}
	}
	if len(pocList) == 0 {
		gologger.Error().Msgf("load 0 nuclei exps")
		return
	}
	gologger.Info().Msgf("load %v nuclei exps", len(pocList))
	var err error
	results, err = r.NucleiExp(target, pocList, payload)
	if err != nil {
		gologger.Error().Msgf("NucleiExp() err, %v", err)
		return
	}

	return
}

// NucleiPoc 扫描
func (r *Runner) NucleiPoc(target string, pocList []*nuclei.Template) (results []*common.Result, err error) {
	// 运行
	input := &inputs.SimpleInputProvider{Inputs: []string{target}}
	_ = r.nucleiEngine.Execute(pocList, input)
	time.Sleep(5 * time.Second) // 战术性 sleep，等待 Interactsh Server 结果
	r.nucleiEngine.WorkPool().Wait()
	// 结果保存
	for _, result := range nuclei.Results {
		result.Target = target
		results = append(results, result)
		gologger.Silent().Msgf("[%v] [%v] [%v] [%v] [%v]", time.Now().Format("2006-01-02 15:04:05"), result.Source, result.PocName, result.Level, result.Extractors)
	}
	nuclei.Results = make([]*common.Result, 0)
	return
}

// NucleiExp 扫描
func (r *Runner) NucleiExp(target string, pocList []*nuclei.Template, payload string) (results []*common.Result, err error) {
	// 运行
	input := &inputs.SimpleInputProvider{Inputs: []string{target}}
	for _, poc := range pocList {
		poc.Variables.Set("exp", base64.StdEncoding.EncodeToString([]byte(payload)))
	}
	_ = r.nucleiEngine.Execute(pocList, input)
	time.Sleep(5 * time.Second) // 战术性 sleep，等待 Interactsh Server 结果
	r.nucleiEngine.WorkPool().Wait()
	// 结果保存
	for _, result := range nuclei.Results {
		result.Target = target
		results = append(results, result)
		gologger.Silent().Msgf("[%v] [%v] [%v] [%v] [%v]", time.Now().Format("2006-01-02 15:04:05"), result.Source, result.PocName, result.Level, result.Extractors)
	}
	nuclei.Results = make([]*common.Result, 0)
	return
}
