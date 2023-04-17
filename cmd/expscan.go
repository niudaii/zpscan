package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/niudaii/zpscan/config"
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/pocscan"
	"github.com/niudaii/zpscan/pkg/pocscan/nuclei"
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"
)

type ExpscanOptions struct {
	Timeout int
	Proxy   string
	Headers []string
	Payload string
}

var (
	expscanOptions ExpscanOptions
)

func init() {
	expscanCmd.Flags().IntVar(&expscanOptions.Timeout, "timeout", 10, "timeout in seconds")
	expscanCmd.Flags().StringVarP(&expscanOptions.Proxy, "proxy", "p", "", "proxy(example: -p 'http://127.0.0.1:8080')")
	expscanCmd.Flags().StringSliceVar(&expscanOptions.Headers, "headers", []string{}, "add custom headers(example: --headers 'User-Agent: xxx,Cookie: xxx')")
	expscanCmd.Flags().StringVar(&expscanOptions.Payload, "payload", "", "payload to send")
	rootCmd.AddCommand(expscanCmd)
}

var expscanCmd = &cobra.Command{
	Use:   "expscan",
	Short: "exp扫描",
	Long:  "exp扫描，支持nuclei",
	Run: func(cmd *cobra.Command, args []string) {
		if err := expscanOptions.validateOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		if err := expscanOptions.configureOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		expscanOptions.run()
	},
}

func (o *ExpscanOptions) validateOptions() error {
	if o.Payload == "" {
		return fmt.Errorf("payload 不能为空")
	}
	return nil
}

func (o *ExpscanOptions) configureOptions() error {
	if o.Proxy == "bp" {
		o.Proxy = "http://127.0.0.1:8080"
	}
	// 加载resource资源
	opt, _ := json.Marshal(o)
	gologger.Debug().Msgf("expscanOptions: %v", string(opt))

	return nil
}

func initExp() (err error) {
	config.Worker.Expscan.NucleiExps, err = nuclei.LoadAllExp(config.Worker.Expscan.NucleiExpDir)
	if err != nil {
		return
	}

	gologger.Info().Msgf("nucleiExps: %v", len(config.Worker.Expscan.NucleiExps))
	return
}

func (o *ExpscanOptions) run() {
	err := initExp()
	if err != nil {
		gologger.Fatal().Msgf("initExp() err, %v", err)
		return
	}
	options := &pocscan.Options{
		Proxy:   expscanOptions.Proxy,
		Timeout: expscanOptions.Timeout,
		Headers: expscanOptions.Headers,
	}
	pocscanRunner, err := pocscan.NewRunner(options, config.Worker.Pocscan.GobyPocs, config.Worker.Pocscan.XrayPocs, config.Worker.Expscan.NucleiExps)
	if err != nil {
		gologger.Error().Msgf("pocscan.NewRunner() err, %v", err)
		return
	}
	scanInputs, err := pocscan.ParseExpInput(targets, expscanOptions.Payload)
	if err != nil {
		gologger.Error().Msgf("pocscan.ParseExpInput() err, %v", err)
		return
	}
	// poc扫描
	results := pocscanRunner.RunExp(scanInputs)
	if len(results) > 0 {
		gologger.Info().Msgf("exp验证成功: %v", len(results))
	}
	// 保存 pocscan 结果
	if commonOptions.ResultFile != "" {
		err = utils.SaveMarshal(commonOptions.ResultFile, results)
		if err != nil {
			gologger.Error().Msgf("utils.SaveMarshal() err, %v", err)
		}
	}
}
