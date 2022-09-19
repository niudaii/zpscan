package portscan

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/niudaii/zpscan/pkg/ipscan/portscan/privileges"
	"github.com/niudaii/zpscan/pkg/ipscan/portscan/scan"
	"github.com/projectdiscovery/blackrock"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ipranger"
	"github.com/projectdiscovery/mapcidr"
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/ratelimit"
)

type Runner struct {
	Options   *Options
	Scanner   *scan.Scanner
	limiter   ratelimit.Limiter
	wgScan    sizedwaitgroup.SizedWaitGroup
	dnsClient *dnsx.DNSX
}

// NewRunner 通过解析配置选项、配置来源、阅读列表等创建一个新的 runner 结构体实例
func (o *Options) NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{
		Options: options,
	}
	Scanner, err := scan.NewScanner(&scan.Options{
		Timeout: time.Duration(options.Timeout) * time.Millisecond,
		Retries: options.Retries,
		Rate:    options.Rate,
		Debug:   options.Debug,
		Proxy:   options.Proxy,
	})
	if err != nil {
		return nil, err
	}
	runner.Scanner = Scanner

	dnsOptions := dnsx.DefaultOptions
	dnsOptions.MaxRetries = runner.Options.Retries
	dnsOptions.Hostsfile = true

	dnsClient, err := dnsx.New(dnsOptions)
	if err != nil {
		return nil, err
	}
	runner.dnsClient = dnsClient

	// 解析扫描目标
	err = runner.ParseTarget()
	if err != nil {
		gologger.Fatal().Msgf("parse target failed: %v", err)
	}

	// 解析扫描端口
	runner.Scanner.Ports, err = ParsePorts(options)
	if err != nil {
		return nil, fmt.Errorf("could not parse ports: %s", err)
	}

	return runner, nil
}

// Run 真正地扫描程序
func (r *Runner) Run() error {
	defer r.Close()
	if privileges.IsPrivileged && r.Options.ScanType == SynScan {
		// 获取本机IP、网卡信息
		err := r.Scanner.TuneSource(ExternalTargetForTune)
		if err != nil {
			return err
		}

		// 监听所有网卡
		err = r.Scanner.SetupHandlers()
		if err != nil {
			return err
		}

		// 启动TCP读写
		r.Scanner.StartListenScan()
	}

	// sizedwaitgroup.New 最大允许启动的goroutine数量
	// rate-limit.New 限制单位时间访问的频率
	r.wgScan = sizedwaitgroup.New(r.Options.Rate)
	r.limiter = ratelimit.New(r.Options.Rate)

	// 判断是否启动syn扫描发包
	useSYN := isOSSupported() && privileges.IsPrivileged && r.Options.ScanType == SynScan

	// 将 ips 缩小到 cidr 的最小值
	var targets []*net.IPNet
	r.Scanner.IPRanger.Hosts.Scan(func(k, v []byte) error {
		targets = append(targets, ipranger.ToCidr(string(k)))
		return nil
	})
	targets, _ = mapcidr.CoalesceCIDRs(targets)
	var targetsCount, portsCount uint64
	for _, target := range targets {
		targetsCount += mapcidr.AddressCountIpnet(target)
	}

	portsCount = uint64(len(r.Scanner.Ports))
	r.Scanner.State = scan.Scan
	Range := targetsCount * portsCount
	bar := pb.StartNew(int(Range))
	currentSeed := time.Now().UnixNano()
	// blackrock基于masscan的黑石密码
	b := blackrock.New(int64(Range), currentSeed)
	for index := int64(0); index < int64(Range); index++ {
		xxx := b.Shuffle(index)
		ipIndex := xxx / int64(portsCount)
		portIndex := int(xxx % int64(portsCount))
		ip := r.PickIP(targets, ipIndex)
		port := r.PickPort(portIndex)
		r.limiter.Take()
		go func(port int) {
			bar.Increment()
			if useSYN {
				// syn扫描
				r.Scanner.EnqueueToTCP(ip, port, scan.SYN)

			} else {
				// 正常扫描
				r.wgScan.Add()
				r.handleHostPort(ip, port)
			}
		}(port)
	}
	bar.Finish()
	r.wgScan.Wait()
	time.Sleep(time.Duration(2) * time.Second)
	r.Scanner.State = scan.Done

	// 如果用户要求进行第二步验证，则验证主机
	if r.Options.Verify {
		r.ConnectVerification()
	}
	r.handleOutput()

	gologger.Info().Msgf("当前共 %v IP 存活\n", len(r.Scanner.ScanResults.IPPorts))
	return nil
}

func (r *Runner) handleHostPort(host string, port int) {
	defer r.wgScan.Done()
	r.limiter.Take()
	open, err := r.Scanner.ConnectPort(host, port, time.Duration(r.Options.Timeout)*time.Millisecond)
	if open && err == nil {
		r.Scanner.ScanResults.AddPort(host, port)
		gologger.Silent().Msgf("%v:%v", host, port)
	}
}

func (r *Runner) ShowScanResultOnExit() {
	r.handleOutput()
}

// Close runner instance
func (r *Runner) Close() {
	r.Scanner.IPRanger.Hosts.Close()
}

// PickIP randomly
func (r *Runner) PickIP(targets []*net.IPNet, index int64) string {
	for _, target := range targets {
		subnetIpsCount := int64(mapcidr.AddressCountIpnet(target))
		if index < subnetIpsCount {
			return r.PickSubnetIP(target, index)
		}
		index -= subnetIpsCount
	}

	return ""
}

func (r *Runner) PickSubnetIP(network *net.IPNet, index int64) string {
	return mapcidr.Inet_ntoa(mapcidr.Inet_aton(network.IP) + index).String()
}

// PickPort 通过算法随机获取端口
func (r *Runner) PickPort(index int) int {
	return r.Scanner.Ports[index]
}

func (r *Runner) ConnectVerification() {
	r.Scanner.State = scan.Scan
	var swg sync.WaitGroup
	limiter := ratelimit.New(r.Options.Rate)
	for host, ports := range r.Scanner.ScanResults.IPPorts {
		limiter.Take()
		swg.Add(1)
		go func(host string, ports map[int]struct{}) {
			defer swg.Done()
			results := r.Scanner.ConnectVerify(host, ports)
			r.Scanner.ScanResults.SetPorts(host, results)
		}(host, ports)
	}

	swg.Wait()
}

func (r *Runner) handleOutput() {
	for hostIP, ports := range r.Scanner.ScanResults.IPPorts {
		// 通过IP获取URL
		dt, err := r.Scanner.IPRanger.GetHostsByIP(hostIP)
		if err != nil {
			continue
		}
		for _, host := range dt {
			if host == "ip" {
				host = hostIP
			}
			gologger.Info().Msgf("Found %d ports on host %s (%s)\n", len(ports), host, hostIP)
		}
	}
}

func isOSSupported() bool {
	return isLinux() || isOSX()
}

func isOSX() bool {
	return runtime.GOOS == "darwin"
}

func isLinux() bool {
	return runtime.GOOS == "linux"
}
