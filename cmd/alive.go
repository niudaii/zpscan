package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/niudaii/zpscan/config"
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/webscan"
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"
)

type AliveOptions struct {
	PortRange string

	Proxy   string
	Threads int
	Timeout int
}

var (
	aliveOptions AliveOptions
)

func init() {
	aliveCmd.Flags().StringVarP(&aliveOptions.PortRange, "port-range", "p", "1-65535", "port range(example: -p '22,80-90,1433,3306')")
	aliveCmd.Flags().IntVar(&aliveOptions.Threads, "threads", 100, "number of threads")
	aliveCmd.Flags().IntVar(&aliveOptions.Timeout, "timeout", 1, "timeout in seconds")
	aliveCmd.Flags().StringVar(&aliveOptions.Proxy, "proxy", "", "proxy(example: -p 'http://127.0.0.1:8080')")

	rootCmd.AddCommand(aliveCmd)
}

var aliveCmd = &cobra.Command{
	Use:   "alive",
	Short: "WEB存活扫描",
	Long:  "WEB存活扫描",
	Run: func(cmd *cobra.Command, args []string) {
		if err := aliveOptions.validateOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		if err := aliveOptions.configureOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		aliveOptions.run()
	},
}

func (o *AliveOptions) validateOptions() error {

	return nil
}

func (o *AliveOptions) configureOptions() error {
	if o.Proxy == "bp" {
		o.Proxy = "http://127.0.0.1:8080"
	}

	opt, _ := json.Marshal(o)
	gologger.Debug().Msgf("aliveOptions: %v", string(opt))

	return nil
}

func (o *AliveOptions) run() {
	ports, err := utils.ParsePortsList(aliveOptions.PortRange)
	if err != nil {
		gologger.Error().Msgf("utils.ParsePortsList() err, %v", err)
		return
	}
	var urls []string
	for _, target := range targets {
		for port := range ports {
			urls = append(urls, fmt.Sprintf("%v:%v", target, port))
		}
	}
	aliveHosts := webscan.CheckAlive(urls, aliveOptions.Timeout, aliveOptions.Threads, aliveOptions.Proxy)
	options := &webscan.Options{
		Proxy:       o.Proxy,
		Threads:     o.Threads,
		Timeout:     o.Timeout,
		Headers:     webscanOptions.Headers,
		NoColor:     commonOptions.NoColor,
		FingerRules: config.Worker.Webscan.FingerRules,
	}
	webRunner, err := webscan.NewRunner(options)
	if err != nil {
		gologger.Error().Msgf("webscan.NewRunner() err, %v", err)
		return
	}
	results := webRunner.Run(aliveHosts)
	if len(results) == 0 {
		gologger.Info().Msgf("结果为空")
		return
	}
	// 保存 Alive 结果
	if commonOptions.ResultFile != "" {
		err = utils.SaveMarshal(commonOptions.ResultFile, results)
		if err != nil {
			gologger.Error().Msgf("utils.SaveMarshal() err, %v", err)
		}
	}
}
