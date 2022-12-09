package nuclei

import (
	"context"
	"github.com/logrusorgru/aurora"
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/pocscan/common"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils/ratelimit"
	"strings"
	"time"
)

type Poc = templates.Template

var (
	Results         []*common.Result
	ExecuterOptions protocols.ExecuterOptions
)

// LoadAllPoc 加载全部poc
func LoadAllPoc(pocDir string) (pocs []*Poc, err error) {
	var pocPathList []string
	pocPathList, err = utils.GetAllFile(pocDir)
	if err != nil {
		return
	}
	for _, pocPath := range pocPathList {
		if !strings.HasSuffix(pocPath, ".yaml") || strings.Contains(pocPath, "workflows") || strings.HasSuffix(pocPath, "-exp.yaml") {
			continue
		}
		var poc *Poc
		poc, err = templates.Parse(pocPath, nil, ExecuterOptions)
		if err != nil {
			gologger.Error().Msgf("ParsePocFile() %v err, %v", pocPath, err)
			continue
		}
		pocs = append(pocs, poc)
	}
	return
}

func InitExecuterOptions(pocDir string) (err error) {
	cache := hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount)
	defer cache.Close()

	mockProgress := &testutils.MockProgressClient{}
	reportingClient, _ := reporting.New(&reporting.Options{}, "")
	defer reportingClient.Close()

	outputWriter := testutils.NewMockOutputWriter()
	outputWriter.WriteCallback = func(event *output.ResultEvent) {
		gologger.Debug().Msgf("加载POC: %v", event.Info.Name)
		if event.MatcherStatus {
			gologger.Debug().Msgf("漏洞存在: %v", event.TemplateID)
			result := &common.Result{
				Source:     "nuclei",
				Level:      event.Info.SeverityHolder.Severity.String(),
				PocName:    event.TemplateID,
				Extractors: strings.Join(event.ExtractedResults, ","),
			}
			Results = append(Results, result)
		}
	}

	options := types.DefaultOptions()

	_ = protocolstate.Init(options)
	_ = protocolinit.Init(options)

	interactOpts := interactsh.NewDefaultOptions(outputWriter, reportingClient, mockProgress)
	interactClient, err := interactsh.New(interactOpts)
	if err != nil {
		return
	}
	defer interactClient.Close()

	catalog := disk.NewCatalog(pocDir)

	ExecuterOptions = protocols.ExecuterOptions{
		Output:          outputWriter,
		Options:         options,
		Progress:        mockProgress,
		Catalog:         catalog,
		IssuesClient:    reportingClient,
		Interactsh:      interactClient,
		RateLimiter:     ratelimit.New(context.Background(), 150, time.Second),
		HostErrorsCache: cache,
		Colorizer:       aurora.NewAurora(true),
		ResumeCfg:       types.NewResumeCfg(),
	}

	return
}

func InitEngine(timeout int, proxy string) (engine *core.Engine) {
	ExecuterOptions.Options.Timeout = timeout
	ExecuterOptions.Options.RateLimit = 5
	ExecuterOptions.Options.ProxyInternal = true
	ExecuterOptions.Options.Proxy = []string{proxy}

	_ = protocolstate.Init(ExecuterOptions.Options)
	_ = protocolinit.Init(ExecuterOptions.Options)
	_ = loadProxyServers(ExecuterOptions.Options) // 初始化代理

	engine = core.New(ExecuterOptions.Options)
	engine.SetExecuterOptions(ExecuterOptions)

	return
}
