package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/niudaii/zpscan/pkg/pocscan"
	"sort"
	"time"

	"github.com/niudaii/zpscan/config"
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/webscan"

	"github.com/imroc/req/v3"
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"
)

type WebscanOptions struct {
	Threads      int
	Timeout      int
	Proxy        string
	Headers      []string
	NoIconhash   bool
	NoShiro      bool
	NoWappalyzer bool

	FilterTags []string
	FingerFile string

	Pocscan bool
}

var (
	webscanOptions WebscanOptions
)

func init() {
	webscanCmd.Flags().IntVar(&webscanOptions.Threads, "threads", 10, "number of threads")
	webscanCmd.Flags().IntVar(&webscanOptions.Timeout, "timeout", 10, "timeout in seconds")
	webscanCmd.Flags().StringVarP(&webscanOptions.Proxy, "proxy", "p", "", "proxy(example: -p 'http://127.0.0.1:8080')")
	webscanCmd.Flags().StringSliceVar(&webscanOptions.Headers, "headers", []string{}, "add custom headers(example: --headers 'User-Agent: xxx,Cookie: xxx')")

	webscanCmd.Flags().BoolVar(&webscanOptions.NoIconhash, "no-iconhash", false, "not scan iconhash")
	webscanCmd.Flags().BoolVar(&webscanOptions.NoShiro, "no-shiro", false, "not scan shiro")
	webscanCmd.Flags().BoolVar(&webscanOptions.NoWappalyzer, "no-wappalyzer", false, "not scan wappalyzer")
	webscanCmd.Flags().StringVar(&webscanOptions.FingerFile, "finger-file", "", "use your finger file(example: --finger-file 'fingers.json')")

	webscanCmd.Flags().StringSliceVar(&webscanOptions.FilterTags, "filter-tags", []string{"非重要"}, "filter tags(example: --filter-tags '非重要')")

	webscanCmd.Flags().BoolVar(&webscanOptions.Pocscan, "pocscan", false, "open pocscan")

	rootCmd.AddCommand(webscanCmd)
}

var webscanCmd = &cobra.Command{
	Use:   "webscan",
	Short: "web信息收集",
	Long:  "web信息收集,获取状态码、标题、指纹等",
	Run: func(cmd *cobra.Command, args []string) {
		if err := webscanOptions.validateOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}
		if err := initFinger(); err != nil {
			gologger.Error().Msgf("initFinger() err, %v", err)
		}

		if err := webscanOptions.configureOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		webscanOptions.run()
	},
}

func (o *WebscanOptions) validateOptions() error {
	if o.FingerFile != "" && !utils.FileExists(o.FingerFile) {
		return fmt.Errorf("file %v does not exist", o.FingerFile)
	}

	return nil
}

func (o *WebscanOptions) configureOptions() error {
	if o.Proxy == "bp" {
		o.Proxy = "http://127.0.0.1:8080"
	}

	opt, _ := json.Marshal(o)
	gologger.Debug().Msgf("webscanOptions: %v", string(opt))

	return nil
}

func initFinger() error {
	// update
	fingerData, err := utils.ReadFile(config.Worker.Webscan.FingerFile)
	if err != nil {
		return err
	}
	if config.Worker.Webscan.UpdateUrl != "" {
		r := req.C().SetTimeout(5 * time.Second).SetCommonRetryCount(3).R()
		resp, err := r.Get(config.Worker.Webscan.UpdateUrl)
		if err != nil {
			return err
		}
		if string(fingerData) != resp.String() {
			err = utils.WriteFile(config.Worker.Webscan.FingerFile, resp.String())
			if err != nil {
				return err
			}
			fingerData = []byte(resp.String())
			gologger.Info().Msgf("当前指纹非最新版本,已获取最新指纹")
		}
	}
	// parse
	if webscanOptions.FingerFile != "" {
		fingerData, err = utils.ReadFile(webscanOptions.FingerFile)
		if err != nil {
			return err
		}
	}
	err = json.Unmarshal(fingerData, &config.Worker.Webscan.FingerRules)
	if err != nil {
		return err
	}
	gologger.Info().Msgf("指纹数量: %v", len(config.Worker.Webscan.FingerRules))

	return nil
}

func (o *WebscanOptions) run() {
	options := &webscan.Options{
		Proxy:        o.Proxy,
		Threads:      o.Threads,
		Timeout:      o.Timeout,
		Headers:      o.Headers,
		NoColor:      commonOptions.NoColor,
		NoShiro:      o.NoShiro,
		NoIconhash:   o.NoIconhash,
		NoWappalyzer: o.NoWappalyzer,
		FingerRules:  config.Worker.Webscan.FingerRules,
	}
	webRunner, err := webscan.NewRunner(options)
	if err != nil {
		gologger.Error().Msgf("webscan.NewRunner() err, %v", err)
		return
	}
	results := webRunner.Run(targets)
	if len(results) == 0 {
		gologger.Info().Msgf("结果为空")
		return
	}
	// 排序并筛选重点指纹
	sort.Sort(results)
	var res string
	var fingerRes string
	var fingerNum int
	for _, result := range results {
		res += webscan.FmtResult(result, options.NoColor)
		// 显示重点指纹
		if len(result.Fingers) > 0 {
			// 过滤tags
			if result.Fingers = webscan.FilterTags(result.Fingers, o.FilterTags); len(result.Fingers) > 0 {
				fingerNum += 1
				fingerRes += webscan.FmtResult(result, options.NoColor)
			}
		}
	}
	gologger.Info().Msgf("存活数量: %v", len(results))
	gologger.Print().Msgf("%v", res)
	if fingerNum > 0 {
		gologger.Info().Msgf("重点指纹: %v", fingerNum)
		gologger.Print().Msgf("%v", fingerRes)
	}
	// 保存 webscan 结果
	if commonOptions.ResultFile != "" {
		err = utils.SaveMarshal(commonOptions.ResultFile, results)
		if err != nil {
			gologger.Error().Msgf("utils.SaveMarshal() err, %v", err)
			return
		}
	}
	// pocscan
	if o.Pocscan {
		err = initPoc()
		if err != nil {
			gologger.Fatal().Msgf("initPoc() err, %v", err)
			return
		}
		options2 := &pocscan.Options{
			Proxy:   o.Proxy,
			Timeout: o.Timeout,
			Headers: o.Headers,
		}
		pocscanRunner, err := pocscan.NewRunner(options2, config.Worker.Pocscan.GobyPocs, config.Worker.Pocscan.XrayPocs, config.Worker.Pocscan.NucleiPocs)
		if err != nil {
			gologger.Error().Msgf("utils.SaveMarshal() err, %v", err)
			return
		}
		var inputs []*pocscan.PocInput
		for _, result := range results {
			if len(result.Fingers) > 0 {
				var pocTags []string
				for _, finger := range result.Fingers {
					pocTags = append(pocTags, finger.PocTags...)
				}
				inputs = append(inputs, &pocscan.PocInput{
					Target:  result.Url,
					PocTags: pocTags,
				})
			}
		}
		pocscanRunner.RunPoc(inputs)
	}
}
