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

func NewRunner(hosts []string, ports, proxy string, process bool, rate, threads int) (r *runner.Runner, err error) {
	options := &runner.Options{
		Host:              hosts,
		Ports:             ports,
		Proxy:             proxy,
		ScanType:          runner.ConnectScan,
		Timeout:           runner.DefaultPortTimeoutConnectScan,
		Retries:           2,
		Verify:            true,
		Rate:              rate,
		Threads:           threads,
		StatsInterval:     5,
		EnableProgressBar: process,
		ResumeCfg:         &runner.ResumeCfg{},
		OnResult: func(result *result.HostResult) {
			gologger.Info().Msgf("%v %v", result.IP, result.Ports)
			Results[result.IP] = result.Ports
		},
	}
	r, err = runner.NewRunner(options)
	return
}
