package cmd

import (
	"encoding/json"
	"github.com/niudaii/zpscan/config"
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/pocscan"
	"github.com/niudaii/zpscan/pkg/pocscan/goby"
	"github.com/niudaii/zpscan/pkg/pocscan/nuclei"
	"github.com/niudaii/zpscan/pkg/pocscan/xray"
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"
)

type PocscanOptions struct {
	Timeout int
	Proxy   string
	Headers []string
}

var (
	pocscanOptions PocscanOptions
)

func init() {
	pocscanCmd.Flags().IntVar(&pocscanOptions.Timeout, "timeout", 10, "timeout in seconds")
	pocscanCmd.Flags().StringVarP(&pocscanOptions.Proxy, "proxy", "p", "", "proxy(example: -p 'http://127.0.0.1:8080')")
	pocscanCmd.Flags().StringSliceVar(&pocscanOptions.Headers, "headers", []string{}, "add custom headers(example: --headers 'User-Agent: xxx,Cookie: xxx')")
	rootCmd.AddCommand(pocscanCmd)
}

var pocscanCmd = &cobra.Command{
	Use:   "pocscan",
	Short: "poc扫描",
	Long:  "poc扫描，支持goby、xray、nuclei",
	Run: func(cmd *cobra.Command, args []string) {
		if err := pocscanOptions.validateOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		if err := pocscanOptions.configureOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		if err := initPoc(); err != nil {
			gologger.Fatal().Msgf("initPoc() err, %v", err)
		}

		pocscanOptions.run()
	},
}

func (o *PocscanOptions) validateOptions() error {

	return nil
}

func (o *PocscanOptions) configureOptions() error {
	if o.Proxy == "bp" {
		o.Proxy = "http://127.0.0.1:8080"
	}
	// 加载resource资源
	opt, _ := json.Marshal(o)
	gologger.Debug().Msgf("pocscanOptions: %v", string(opt))

	return nil
}

func initPoc() error {
	var err error
	config.Worker.Pocscan.GobyPocs, err = goby.LoadAllPoc(config.Worker.Pocscan.GobyPocDir)
	if err != nil {
		return err
	}
	config.Worker.Pocscan.XrayPocs, err = xray.LoadAllPoc(config.Worker.Pocscan.XrayPocDir)
	if err != nil {
		return err
	}
	err = nuclei.InitNuclei(config.Worker.Pocscan.NucleiPocDir, 5, pocscanOptions.Timeout, pocscanOptions.Proxy)
	if err != nil {
		return err
	}
	config.Worker.Pocscan.NucleiPocs, err = nuclei.LoadAllPoc(config.Worker.Pocscan.NucleiPocDir)
	if err != nil {
		return err
	}
	gologger.Info().Msgf("gobyPocs: %v", len(config.Worker.Pocscan.GobyPocs))
	gologger.Info().Msgf("xrayPocs: %v", len(config.Worker.Pocscan.XrayPocs))
	gologger.Info().Msgf("nucleiPocs: %v", len(config.Worker.Pocscan.NucleiPocs))
	return nil
}

func (o *PocscanOptions) run() {
	options := &pocscan.Options{
		Proxy:   pocscanOptions.Proxy,
		Timeout: pocscanOptions.Timeout,
		Headers: pocscanOptions.Headers,
	}
	pocscanRunner, err := pocscan.NewRunner(options, config.Worker.Pocscan.GobyPocs, config.Worker.Pocscan.XrayPocs, config.Worker.Pocscan.NucleiPocs)
	if err != nil {
		gologger.Error().Msgf("pocscan.NewRunner() err, %v", err)
		return
	}
	scanInputs, err := pocscan.ParseTargets(targets)
	if err != nil {
		gologger.Error().Msgf("pocscan.ParseTargets() err, %v", err)
		return
	}
	// poc扫描
	results := pocscanRunner.Run(scanInputs)
	if len(results) > 0 {
		gologger.Info().Msgf("poc验证成功: %v", len(results))
	}
	// 保存 pocscan 结果
	if commonOptions.ResultFile != "" {
		err = utils.SaveMarshal(commonOptions.ResultFile, results)
		if err != nil {
			gologger.Error().Msgf("utils.SaveMarshal() err, %v", err)
		}
	}
}
