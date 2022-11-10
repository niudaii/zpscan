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
	reqClient  *req.Client
}

func NewRunner(options *Options, gobyPocs []*goby.Poc, xrayPocs []*xray.Poc, nucleiPcs []*nuclei.Poc) (runner *Runner, err error) {
	runner = &Runner{
		gobyPocs:   gobyPocs,
		xrayPocs:   xrayPocs,
		nucleiPocs: nucleiPcs,
		reqClient:  utils.NewReqClient(options.Proxy, options.Timeout, options.Headers),
	}
	return runner, nil
}

func (r *Runner) Run(targets []string, pocTags []string) (results []*common.Result) {
	for _, target := range targets {
		results = append(results, r.Pocscan(target, pocTags)...)
	}
	return
}

func (r *Runner) Pocscan(target string, pocTags []string) (results []*common.Result) {
	gologger.Info().Msgf("开始poc扫描: %v", target)

	for _, pocTag := range pocTags {
		gologger.Info().Msgf("pocTag: %v", pocTag)
		results = append(results, r.RunGobyPoc(target, pocTag)...)
		results = append(results, r.RunXrayPoc(target, pocTag)...)
		results = append(results, r.RunNucleiPoc(target, pocTag)...)
	}
	if len(results) == 0 {
		gologger.Info().Msgf("不存在漏洞")
	}
	return
}
