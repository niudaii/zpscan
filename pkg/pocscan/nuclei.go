package pocscan

import (
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/pocscan/common"
	"github.com/niudaii/zpscan/pkg/pocscan/nuclei"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs"
	"strings"
	"time"
)

// RunNucleiPoc 启动
func (r *Runner) RunNucleiPoc(target string, pocTag string) (results []*common.Result) {
	var pocList []*nuclei.Poc
	for _, poc := range r.nucleiPocs {
		// 判断 ID 和 tags
		if strings.Contains(strings.ToLower(poc.ID), pocTag) || utils.HasStr(poc.Info.Tags.ToSlice(), pocTag) {
			pocList = append(pocList, poc)
		}
	}
	if len(pocList) == 0 {
		gologger.Error().Msgf("load 0 nuclei pocs")
		return
	}
	gologger.Info().Msgf("load %v nuclei pocs", len(pocList))
	var err error
	results, err = r.ScanNuclei(target, pocList, pocTag)
	if err != nil {
		gologger.Error().Msgf("ScanNuclei() err, %v", err)
		return
	}

	return
}

// ScanNuclei 扫描
func (r *Runner) ScanNuclei(target string, pocList []*nuclei.Poc, pocTag string) (results []*common.Result, err error) {
	// 运行
	input := &inputs.SimpleInputProvider{Inputs: []string{target}}
	_ = nuclei.Engine.Execute(pocList, input)
	time.Sleep(5 * time.Second) // 战术性 sleep，等待 Interactsh Server 结果
	nuclei.Engine.WorkPool().Wait()
	// 结果保存
	for _, result := range nuclei.Results {
		result.Target = target
		result.PocTag = pocTag
		results = append(results, result)
		gologger.Silent().Msgf("[%v] [%v] [%v] [%v] [%v]", time.Now().Format("2006-01-02 15:04:05"), result.Source, result.PocName, result.Level, result.Extractors)
	}
	nuclei.Results = make([]*common.Result, 0)
	return
}
