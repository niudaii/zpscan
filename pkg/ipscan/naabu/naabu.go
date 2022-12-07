package naabu

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

type Result map[string][]int

var (
	Results = make(Result)
)

func NewRunner(hosts []string, ports, proxy string) (r *runner.Runner, err error) {
	options := &runner.Options{
		Host:              hosts,
		Ports:             ports,
		Proxy:             proxy,
		ResumeCfg:         &runner.ResumeCfg{},
		Retries:           1,
		Verify:            true,
		ScanType:          runner.ConnectScan,
		Rate:              runner.DefaultRateConnectScan,
		Threads:           5,
		StatsInterval:     5,
		EnableProgressBar: true,
		OnResult: func(result *result.HostResult) {
			gologger.Info().Msgf("%v %v", result.IP, result.Ports)
			Results[result.IP] = result.Ports
		},
	}
	if proxy != "" {
		options.Ping = true
	}
	r, err = runner.NewRunner(options)
	return
}
