package cmd

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/niudaii/zpscan/config"
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/dirscan"

	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"
)

type DirscanOptions struct {
	Proxy   string
	Threads int
	Timeout int
	Headers []string

	DirFile     string
	DirLang     string
	DirTypes    []string
	MaxMatched  int
	MatchStatus []int
}

var (
	dirscanOptions DirscanOptions
	dirData        []string
)

func init() {
	dirscanCmd.Flags().IntVar(&dirscanOptions.Threads, "threads", 10, "number of threads")
	dirscanCmd.Flags().IntVar(&dirscanOptions.Timeout, "timeout", 5, "timeout in seconds")
	dirscanCmd.Flags().StringVarP(&dirscanOptions.Proxy, "proxy", "p", "", "proxy(example: -p 'http://127.0.0.1:8080')")
	dirscanCmd.Flags().StringSliceVar(&dirscanOptions.Headers, "headers", []string{}, "add custom headers(example: --headers 'User-Agent: xxx,Cookie: xxx')")

	dirscanCmd.Flags().StringVar(&dirscanOptions.DirFile, "dir-file", "", "dir file(example: --dir-file 'xxx.txt')")
	dirscanCmd.Flags().StringSliceVar(&dirscanOptions.DirTypes, "dir-types", []string{"backup", "catalog", "api", "leak", "vuln"}, "dit types")
	dirscanCmd.Flags().StringVar(&dirscanOptions.DirLang, "dir-lang", "", "dir lang(php|asp|jsp...)")

	dirscanCmd.Flags().IntSliceVar(&dirscanOptions.MatchStatus, "match-status", []int{200, 204, 301, 302, 307, 401, 405}, "match status")
	dirscanCmd.Flags().IntVar(&dirscanOptions.MaxMatched, "max-matched", 30, "discard result if it more than max matched")

	rootCmd.AddCommand(dirscanCmd)
}

var dirscanCmd = &cobra.Command{
	Use:   "dirscan",
	Short: "目录扫描",
	Long:  "目录扫描",
	Run: func(cmd *cobra.Command, args []string) {
		if err := dirscanOptions.validateOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		if err := initDirMap(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		if err := dirscanOptions.configureOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		dirscanOptions.run()
	},
}

func (o *DirscanOptions) validateOptions() error {
	if o.DirFile != "" && !utils.FileExists(o.DirFile) {
		return fmt.Errorf("file %v does not exist", o.DirFile)
	}

	return nil
}

func (o *DirscanOptions) configureOptions() error {
	if o.Proxy == "bp" {
		o.Proxy = "http://127.0.0.1:8080"
	}

	if o.DirFile != "" {
		var err error
		if dirData, err = utils.ReadLines(o.DirFile); err != nil {
			return err
		}
	} else {
		if o.DirLang != "" {
			for _, prefix := range config.Worker.Dirscan.DirMap["common"] {
				dirData = append(dirData, prefix+"."+o.DirLang)
			}
		}
		for _, dirType := range o.DirTypes {
			gologger.Info().Msgf("%v: %v", dirType, len(config.Worker.Dirscan.DirMap[dirType]))
			dirData = append(dirData, config.Worker.Dirscan.DirMap[dirType]...)
		}
	}

	opt, _ := json.Marshal(o)
	gologger.Debug().Msgf("当前配置: %v", string(opt))
	gologger.Info().Msgf("目录字典: %v", len(dirData))

	return nil
}

func initDirMap() error {
	var err error
	config.Worker.Dirscan.DirMap = map[string][]string{}
	if config.Worker.Dirscan.DirMap["api"], err = utils.ReadLines(config.Worker.Dirscan.ApiFile); err != nil {
		return err
	}
	if config.Worker.Dirscan.DirMap["catalog"], err = utils.ReadLines(config.Worker.Dirscan.CatalogFile); err != nil {
		return err
	}
	if config.Worker.Dirscan.DirMap["common"], err = utils.ReadLines(config.Worker.Dirscan.CommonFile); err != nil {
		return err
	}
	if config.Worker.Dirscan.DirMap["leak"], err = utils.ReadLines(config.Worker.Dirscan.LeakFile); err != nil {
		return err
	}
	if config.Worker.Dirscan.DirMap["vuln"], err = utils.ReadLines(config.Worker.Dirscan.VulnFile); err != nil {
		return err
	}
	if backupPrefix, err := utils.ReadLines(config.Worker.Dirscan.BackupFile); err != nil {
		return err
	} else {
		for _, prefix := range backupPrefix {
			for _, suffix := range config.Worker.Dirscan.BackupSuffix {
				config.Worker.Dirscan.DirMap["backup"] = append(config.Worker.Dirscan.DirMap["backup"], prefix+"."+suffix)
			}
		}
	}

	return nil
}

func (o *DirscanOptions) run() {
	options := &dirscan.Options{
		Proxy:       o.Proxy,
		Threads:     o.Threads,
		Timeout:     o.Timeout,
		Headers:     o.Headers,
		MaxMatched:  o.MaxMatched,
		MatchStatus: o.MatchStatus,
	}
	dirscanRunner, err := dirscan.NewRunner(options)
	if err != nil {
		gologger.Error().Msgf("dirscan.NewRunner() err, %v", err)
		return
	}
	var input []*dirscan.Input
	for _, target := range targets {
		input = append(input, &dirscan.Input{
			Target: target,
			Dirs:   dirData,
		})
	}
	results := dirscanRunner.Run(input)
	sort.Sort(results)
	gologger.Info().Msgf("结果数量: %v", len(results))
	for _, result := range results {
		gologger.Print().Msgf("%v [%v] [%v] [%v]", result.Url, result.StatusCode, result.ContentLength, result.Title)
	}
	// 保存 dirscan 结果
	if commonOptions.ResultFile != "" {
		err = utils.SaveMarshal(commonOptions.ResultFile, results)
		if err != nil {
			gologger.Error().Msgf("utils.SaveMarshal() err, %v", err)
		}
	}
}
