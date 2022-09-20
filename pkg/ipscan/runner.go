package ipscan

import (
	"github.com/niudaii/zpscan/pkg/ipscan/portfinger"
	"github.com/niudaii/zpscan/pkg/ipscan/portscan"
	"github.com/niudaii/zpscan/pkg/ipscan/qqwry"
	"github.com/projectdiscovery/gologger"
)

type Options struct {
	Hosts     []string
	PortRange string
	Rate      int
	Threads   int
	MaxPort   int
	QQwry     *qqwry.QQwry
	NmapProbe *portfinger.NmapProbe
}

type Runner struct {
	options          *Options
	synscanRunner    *portscan.Runner
	portFingerEngine *portfinger.Engine
}

func NewRunner(options *Options) (*Runner, error) {
	synscanOptions := &portscan.Options{
		Host:      options.Hosts,
		Ports:     options.PortRange,
		Threads:   options.Threads,
		Timeout:   portscan.DefaultPortTimeoutSynScan,
		ScanType:  portscan.ConnectScan,
		Rate:      options.Rate,
		Retries:   portscan.DefaultRetriesSynScan,
		Interface: "",
	}
	synscanRunner, err := synscanOptions.NewRunner(synscanOptions)
	if err != nil {
		return nil, err
	}
	portFingerEngine, err := portfinger.NewEngine(200, options.NmapProbe)
	if err != nil {
		return nil, err
	}
	return &Runner{
		options:          options,
		synscanRunner:    synscanRunner,
		portFingerEngine: portFingerEngine,
	}, nil
}

func (r *Runner) Run() (results []*portfinger.Result) {
	gologger.Info().Msgf("开始端口扫描")

	err := r.synscanRunner.Run()
	if err != nil {
		gologger.Error().Msgf("synscanRunner.Run() err, %v", err)
		return
	}
	portscanResult := r.synscanRunner.Scanner.ScanResults.IPPorts
	if len(portscanResult) == 0 {
		return
	}
	// 去除开放端口数大于maxPort
	for k := range portscanResult {
		ports := portscanResult[k]
		if len(ports) > r.options.MaxPort {
			gologger.Info().Msgf("%v 开放端口大于 %v", k, r.options.MaxPort)
			portscanResult[k] = map[int]struct{}{}
		}
	}
	// 开放的端口使用nmap指纹识别
	gologger.Info().Msgf("端口协议识别")
	results = r.portFingerEngine.Run(portscanResult)

	return
}
