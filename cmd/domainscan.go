package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/niudaii/zpscan/config"
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/domainscan"
	"github.com/niudaii/zpscan/pkg/domainscan/domainweb"
	"github.com/niudaii/zpscan/pkg/webscan"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"github.com/spf13/cobra"
)

type DomainscanOptions struct {
	ProviderFile  string
	SubdomainFile string
	SubnextFile   string

	Layer int
	Rate  string
}

var domainscanOptions DomainscanOptions

func init() {
	domainscanCmd.Flags().IntVarP(&domainscanOptions.Layer, "layer", "l", 1, "number of domain layer(1|2)")
	domainscanCmd.Flags().StringVar(&domainscanOptions.Rate, "rate", "500000k", "ksubdomain rate")
	domainscanCmd.Flags().StringVar(&domainscanOptions.ProviderFile, "provider-file", "", "subfinder provider config file(example: --provider-config 'xxx.yaml')")
	domainscanCmd.Flags().StringVar(&domainscanOptions.SubdomainFile, "subdomain-file", "", "subdomain file(example: --subdomain-file 'xxx.txt')")
	domainscanCmd.Flags().StringVar(&domainscanOptions.SubnextFile, "subnext-file", "", "subnext file(example: --subnext-file 'xxx.txt')")

	rootCmd.AddCommand(domainscanCmd)
}

var domainscanCmd = &cobra.Command{
	Use:   "domainscan",
	Short: "子域名收集",
	Long:  "子域名收集,subfinder被动收集,ksubdomain进行dns验证",
	Run: func(cmd *cobra.Command, args []string) {
		if err := domainscanOptions.validateOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		if err := initFinger(); err != nil {
			gologger.Error().Msgf("initFinger() err, %v", err)
		}

		if err := initProviders(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		if err := domainscanOptions.configureOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		domainscanOptions.run()
	},
}

func (o *DomainscanOptions) validateOptions() error {
	if o.ProviderFile != "" && !utils.FileExists(o.ProviderFile) {
		return fmt.Errorf("file %v does not exist", o.ProviderFile)
	}
	if o.SubdomainFile != "" && !utils.FileExists(o.SubdomainFile) {
		return fmt.Errorf("file %v does not exist", o.SubdomainFile)
	}
	if o.SubnextFile != "" && !utils.FileExists(o.SubnextFile) {
		return fmt.Errorf("file %v does not exist", o.SubnextFile)
	}

	return nil
}

func (o *DomainscanOptions) configureOptions() error {
	var err error
	if o.SubdomainFile != "" {
		config.Worker.Domainscan.SubdomainFile = o.SubdomainFile
	}
	if o.SubnextFile != "" {
		config.Worker.Domainscan.SubnextFile = o.SubnextFile
	}

	if config.Worker.Domainscan.SubdomainData, err = utils.ReadLines(config.Worker.Domainscan.SubdomainFile); err != nil {
		return err
	}
	if config.Worker.Domainscan.SubnextData, err = utils.ReadLines(config.Worker.Domainscan.SubnextFile); err != nil {
		return err
	}
	if config.Worker.Domainscan.CdnCnameData, err = utils.ReadLines(config.Worker.Domainscan.CdnCnameFile); err != nil {
		return err
	}
	if config.Worker.Domainscan.CdnIpData, err = utils.ReadLines(config.Worker.Domainscan.CdnIpFile); err != nil {
		return err
	}

	config.Worker.Domainscan.SubdomainData = utils.RemoveDuplicate(config.Worker.Domainscan.SubdomainData)
	config.Worker.Domainscan.SubnextData = utils.RemoveDuplicate(config.Worker.Domainscan.SubnextData)

	opt, _ := json.Marshal(o)
	gologger.Debug().Msgf("当前配置: %v", string(opt))
	gologger.Info().Msgf("SubdomainData: %v", len(config.Worker.Domainscan.SubdomainData))
	gologger.Info().Msgf("SubnextData: %v", len(config.Worker.Domainscan.SubnextData))

	return nil
}

func initProviders() error {
	config.Worker.Domainscan.Providers = &runner.Providers{}
	if domainscanOptions.ProviderFile == "" {
		domainscanOptions.ProviderFile = config.Worker.Domainscan.ProviderFile
	}
	err := config.Worker.Domainscan.Providers.UnmarshalFrom(domainscanOptions.ProviderFile)
	return err
}

func (o *DomainscanOptions) run() {
	// 子域名收集
	options := &domainscan.Options{
		Layer:         o.Layer,
		Rate:          o.Rate,
		SubdomainData: config.Worker.Domainscan.SubdomainData,
		SubnextData:   config.Worker.Domainscan.SubnextData,
		CdnCnameData:  config.Worker.Domainscan.CdnCnameData,
		CdnIpData:     config.Worker.Domainscan.CdnIpData,
		Providers:     config.Worker.Domainscan.Providers,
	}
	domainscanRunner, err := domainscan.NewRunner(options)
	if err != nil {
		gologger.Error().Msgf("domainscan.NewRunner() err, %v", err)
		return
	}
	results := domainscanRunner.Run(targets)
	if len(results) > 0 {
		gologger.Info().Msgf("子域名结果: %v", len(results))
	}
	var urls []string
	for _, result := range results {
		urls = append(urls, result.Domain)
	}
	for _, target := range targets {
		tmpUrls, err := domainweb.Run(target, config.Worker.Domainscan.FofaEmail, config.Worker.Domainscan.FofaKey)
		if err != nil {
			gologger.Error().Msgf("domainweb.Run() err, %v", err)
			continue
		}
		urls = append(urls, tmpUrls...)
	}
	urls = utils.RemoveDuplicate(urls)
	gologger.Info().Msgf("domain web: %v", len(urls))
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
	webscanRunner.Run(urls)
	// 保存 domainscan 结果
	if commonOptions.ResultFile != "" {
		err = utils.SaveMarshal(commonOptions.ResultFile, results)
		if err != nil {
			gologger.Error().Msgf("utils.SaveMarshal() err, %v", err)
		}
	}
}
