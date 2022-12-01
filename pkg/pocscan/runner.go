package pocscan

import (
	"github.com/imroc/req/v3"
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/pocscan/common"
	"github.com/niudaii/zpscan/pkg/pocscan/goby"
	"github.com/niudaii/zpscan/pkg/pocscan/nuclei"
	"github.com/niudaii/zpscan/pkg/pocscan/xray"
	"github.com/projectdiscovery/gologger"
)

type Options struct {
	Proxy   string
	Timeout int
	Headers []string
}

type Runner struct {
	gobyPocs   []*goby.Poc
	xrayPocs   []*xray.Poc
	nucleiPocs []*nuclei.Poc
	nucleiExps []*nuclei.Poc
	reqClient  *req.Client
}

func NewRunner(options *Options, gobyPocs []*goby.Poc, xrayPocs []*xray.Poc, nucleiPcs []*nuclei.Poc, nucleiExps []*nuclei.Exp) (runner *Runner, err error) {
	runner = &Runner{
		gobyPocs:   gobyPocs,
		xrayPocs:   xrayPocs,
		nucleiPocs: nucleiPcs,
		nucleiExps: nucleiExps,
		reqClient:  utils.NewReqClient(options.Proxy, options.Timeout, options.Headers),
	}
	return runner, nil
}

type PocInput struct {
	Target  string
	PocTags []string
}

type ExpInput struct {
	Target  string
	PocName string
	Payload string
}

func (r *Runner) RunPoc(inputs []*PocInput) (results []*common.Result) {
	for _, input := range inputs {
		results = append(results, r.Pocscan(input)...)
	}
	return
}

func (r *Runner) RunExp(inputs []*ExpInput) (results []*common.Result) {
	for _, input := range inputs {
		results = append(results, r.Expscan(input)...)
	}
	return
}

func (r *Runner) Pocscan(input *PocInput) (results []*common.Result) {
	gologger.Info().Msgf("开始poc扫描: %v", input.Target)

	for _, pocTag := range input.PocTags {
		gologger.Info().Msgf("pocTag: %v", pocTag)
		results = append(results, r.RunGobyPoc(input.Target, pocTag)...)
		results = append(results, r.RunXrayPoc(input.Target, pocTag)...)
		results = append(results, r.RunNucleiPoc(input.Target, pocTag)...)
	}
	if len(results) == 0 {
		gologger.Info().Msgf("不存在漏洞")
	}
	return
}

func (r *Runner) Expscan(input *ExpInput) (results []*common.Result) {
	gologger.Info().Msgf("开始exp扫描: %v", input.Target)

	gologger.Info().Msgf("pocName: %v", input.PocName)
	results = append(results, r.RunNucleiExp(input.Target, input.PocName, input.Payload)...)

	if len(results) == 0 {
		gologger.Info().Msgf("不存在漏洞")
	}
	return
}
