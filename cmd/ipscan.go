package cmd

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/niudaii/zpscan/pkg/webscan"
	"strings"

	"github.com/niudaii/zpscan/config"
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/crack"
	"github.com/niudaii/zpscan/pkg/ipscan"
	"github.com/niudaii/zpscan/pkg/ipscan/portfinger"
	"github.com/niudaii/zpscan/pkg/ipscan/portscan"
	"github.com/niudaii/zpscan/pkg/ipscan/qqwry"

	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"
	"github.com/zu1k/nali/pkg/common"
)

type IpscanOptions struct {
	PortRange string
	Rate      int
	Threads   int

	MaxPort int

	Crack bool
}

var ipscanOptions IpscanOptions

func init() {
	ipscanCmd.Flags().StringVarP(&ipscanOptions.PortRange, "port-range", "p", "1-65535", "port range(example: -p '22,80-90,1433,3306')")
	ipscanCmd.Flags().IntVar(&ipscanOptions.Rate, "rate", 3000, "packets to send per second")
	ipscanCmd.Flags().IntVar(&ipscanOptions.Threads, "threads", 10, "number of threads")

	ipscanCmd.Flags().IntVar(&ipscanOptions.MaxPort, "max-port", 200, "discard result if it more than max port")

	ipscanCmd.Flags().BoolVar(&ipscanOptions.Crack, "crack", false, "open crack")

	rootCmd.AddCommand(ipscanCmd)
}

var ipscanCmd = &cobra.Command{
	Use:   "ipscan",
	Short: "端口扫描",
	Long:  "端口扫描,对结果进行webscan扫描, 可选crack",
	Run: func(cmd *cobra.Command, args []string) {
		if err := ipscanOptions.validateOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		if err := initFinger(); err != nil {
			gologger.Error().Msgf("initFinger() err, %v", err)
		}

		if err := initQqwry(); err != nil {
			gologger.Fatal().Msgf("initQqwry() err, %v", err)
		}

		if err := initNmapProbe(); err != nil {
			gologger.Fatal().Msgf("initNmapProbe() err, %v", err)
		}

		if err := ipscanOptions.configureOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		ipscanOptions.run()
	},
}

func (o *IpscanOptions) validateOptions() error {
	return nil
}

func (o *IpscanOptions) configureOptions() error {
	opt, _ := json.Marshal(o)
	gologger.Debug().Msgf("当前配置: %v", string(opt))

	return nil
}

func initQqwry() error {
	fileData, err := utils.ReadFile(config.Worker.Ipscan.QqwryFile)
	if err != nil {
		return err
	}
	var fileInfo common.FileData
	fileInfo.Data = fileData
	buf := fileInfo.Data[0:8]
	start := binary.LittleEndian.Uint32(buf[:4])
	end := binary.LittleEndian.Uint32(buf[4:])
	config.Worker.Ipscan.Qqwry = &qqwry.QQwry{
		IPDB: common.IPDB{
			Data:  &fileInfo,
			IPNum: (end-start)/7 + 1,
		},
	}
	return nil
}

func initNmapProbe() error {
	config.Worker.Ipscan.NmapProbe = &portfinger.NmapProbe{}
	nmapData, err := utils.ReadFile(config.Worker.Ipscan.NmapFile)
	if err != nil {
		return err
	}
	if err = config.Worker.Ipscan.NmapProbe.Init(nmapData); err != nil {
		return err
	}
	gologger.Info().Msgf("nmap指纹数量: %v个探针,%v条正则", len(config.Worker.Ipscan.NmapProbe.Probes), config.Worker.Ipscan.NmapProbe.Count())
	return nil
}

type Ip struct {
	Ip      string
	Ports   string
	Country string
	Area    string
	OS      string
}

type Service struct {
	Address  string
	Protocol string
	Version  string
}

func (o *IpscanOptions) run() {
	var hosts []string
	for _, target := range targets {
		tmpHosts, err := portscan.ParseIP(target)
		if err != nil {
			return
		}
		hosts = append(hosts, tmpHosts...)
	}
	options := &ipscan.Options{
		Hosts:     hosts,
		PortRange: o.PortRange,
		Rate:      o.Rate,
		Threads:   o.Threads,
		MaxPort:   o.MaxPort,
		QQwry:     config.Worker.Ipscan.Qqwry,
		NmapProbe: config.Worker.Ipscan.NmapProbe,
	}
	ipscanRunner, err := ipscan.NewRunner(options)
	if err != nil {
		gologger.Error().Msgf("ipscan.NewRunner() err, %v", err)
		return
	}
	var ipResults []*Ip
	var servResults []*Service
	for _, ip := range hosts {
		ipResult := &Ip{
			Ip: ip,
		}
		// 获取地理位置
		if ipResult.Country, ipResult.Area, err = ipscanRunner.GetIpAddr(ip); err != nil {
			gologger.Error().Msgf("ipscanRunner.GetIpAddr() err, %v", err)
			return
		}
		// 操作系统识别
		if ipResult.OS, err = ipscan.CheckOS(ip); err != nil {
			gologger.Error().Msgf("ipscan.CheckOS() err, %v", err)
			return
		}
		gologger.Info().Msgf("%v [%v %v] [%v]", ipResult.Ip, ipResult.Country, ipResult.Area, ipResult.OS)
		ipResults = append(ipResults, ipResult)
	}
	// 端口扫描
	portscanResults := ipscanRunner.Run()
	if len(portscanResults) == 0 {
		gologger.Info().Msgf("端口扫描结果为空")
		return
	}
	ipPortMap := make(map[string][]string)
	for _, result := range portscanResults {
		t := strings.Split(result.Addr, ":")
		ip := t[0]
		port := t[1]
		ipPortMap[ip] = append(ipPortMap[ip], port)
	}
	for _, ipResult := range ipResults {
		ipResult.Ports = strings.Join(ipPortMap[ipResult.Ip], ",")
	}
	// 结果处理
	var webTargets []string
	var crackTargets []string
	for _, portscanResult := range portscanResults {
		t := strings.Split(portscanResult.Addr, ":")
		ip := t[0]
		port := t[1]
		// unknown 服务也使用 webscan
		if portscanResult.ServiceName == "ssl" {
			if port == "443" {
				webTargets = append(webTargets, "https://"+ip)
			} else {
				webTargets = append(webTargets, "https://"+ip+":"+port)
			}
		} else if portscanResult.ServiceName == "http" {
			if port == "80" {
				webTargets = append(webTargets, "http://"+ip)
			} else {
				webTargets = append(webTargets, "http://"+ip+":"+port)
			}
		} else if portscanResult.ServiceName == "unknown" {
			webTargets = append(webTargets, ip+":"+port)
		} else {
			servResults = append(servResults, &Service{
				Address:  portscanResult.Addr,
				Protocol: portscanResult.ServiceName,
				Version:  fmt.Sprintf("%v %v", portscanResult.VendorProduct, portscanResult.Version),
			})
			if crack.SupportProtocols[portscanResult.ServiceName] {
				crackTargets = append(crackTargets, portscanResult.Addr+"|"+portscanResult.ServiceName)
			}
		}
	}
	gologger.Info().Msgf("web: %v", len(webTargets))
	gologger.Info().Msgf("service: %v", len(servResults))
	gologger.Info().Msgf("crack: %v", len(crackTargets))
	options2 := &webscan.Options{
		Proxy:       webscanOptions.Proxy,
		Threads:     webscanOptions.Threads,
		Timeout:     webscanOptions.Timeout,
		Headers:     webscanOptions.Headers,
		NoColor:     commonOptions.NoColor,
		FingerRules: config.Worker.Webscan.FingerRules,
	}
	webscanRunner, err := webscan.NewRunner(options2)
	if err != nil {
		gologger.Error().Msgf("webscan.NewRunner() err, %v", err)
		return
	}
	webscanRunner.Run(webTargets)
	if o.Crack {
		options3 := &crack.Options{
			Threads:  crackOptions.Threads,
			Timeout:  crackOptions.Timeout,
			Delay:    crackOptions.Delay,
			CrackAll: crackOptions.CrackAll,
		}
		crackRunner, err := crack.NewRunner(options3)
		if err != nil {
			gologger.Error().Msgf("crack.NewRunner() err, %v", err)
			return
		}
		addrs := crack.ParseTargets(crackTargets)
		addrs = crack.FilterModule(addrs, crackOptions.Module)
		crackRunner.Run(addrs, []string{}, []string{})
	}
}
