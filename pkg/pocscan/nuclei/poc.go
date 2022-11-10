package nuclei

import (
	"context"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/niudaii/zpscan/internal/utils"
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
	ExecuterOptions protocols.ExecuterOptions
	Engine          *core.Engine
)

// LoadAllPoc 加载全部poc
func LoadAllPoc(pocDir string) (pocs []*Poc, err error) {
	var pocPathList []string
	pocPathList, err = utils.GetAllFile(pocDir)
	if err != nil {
		return
	}
	for _, pocPath := range pocPathList {
		if !strings.HasSuffix(pocPath, ".yaml") || strings.Contains(pocPath, "workflows") {
			continue
		}
		var poc *Poc
		poc, err = ParsePocFile(pocPath)
		if err != nil {
			gologger.Error().Msgf("ParsePocFile() %v err, %v", pocPath, err)
			continue
		}
		pocs = append(pocs, poc)
	}
	return
}

func ParsePocFile(filePath string) (template *templates.Template, err error) {
	template, err = templates.Parse(filePath, nil, ExecuterOptions)
	return
}

func InitNuclei(pocDir string, limiter, timeout int, proxy string) (err error) {
	cache := hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount)
	defer cache.Close()

	mockProgress := &testutils.MockProgressClient{}
	reportingClient, _ := reporting.New(&reporting.Options{}, "")
	defer reportingClient.Close()

	outputWriter := testutils.NewMockOutputWriter()
	var results []string
	outputWriter.WriteCallback = func(event *output.ResultEvent) {
		results = append(results, fmt.Sprintf("%v\n", event))
	}

	defaultOpts := types.DefaultOptions()
	defaultOpts.Timeout = timeout
	defaultOpts.Proxy = []string{proxy}
	defaultOpts.RateLimit = limiter

	_ = protocolstate.Init(defaultOpts)
	_ = protocolinit.Init(defaultOpts)
	_ = loadProxyServers(defaultOpts) //

	interactOpts := interactsh.NewDefaultOptions(outputWriter, reportingClient, mockProgress)
	var interactClient *interactsh.Client
	interactClient, err = interactsh.New(interactOpts)
	if err != nil {
		return
	}
	defer interactClient.Close()

	catalog := disk.NewCatalog(pocDir)

	ExecuterOptions = protocols.ExecuterOptions{
		Output:          outputWriter,
		Options:         defaultOpts,
		Progress:        mockProgress,
		Catalog:         catalog,
		IssuesClient:    reportingClient,
		RateLimiter:     ratelimit.New(context.Background(), 150, time.Second),
		Interactsh:      interactClient,
		HostErrorsCache: cache,
		Colorizer:       aurora.NewAurora(true),
		ResumeCfg:       types.NewResumeCfg(),
	}
	Engine = core.New(defaultOpts)
	Engine.SetExecuterOptions(ExecuterOptions)

	return nil
}
