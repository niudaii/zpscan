package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/niudaii/zpscan/config"
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/crack"

	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"
)

type CrackOptions struct {
	Module   string
	User     string
	Pass     string
	UserFile string
	PassFile string

	Threads  int
	Timeout  int
	Delay    int
	CrackAll bool
}

var (
	crackOptions CrackOptions
	userDict     []string
	passDict     []string
)

func init() {
	crackCmd.Flags().StringVarP(&crackOptions.Module, "module", "m", "all", "choose one module to crack(ftp,ssh,wmi,mssql,oracle,mysql,rdp,postgres,redis,memcached,mongodb)")
	crackCmd.Flags().StringVar(&crackOptions.User, "user", "", "user(example: --user 'admin,root')")
	crackCmd.Flags().StringVar(&crackOptions.Pass, "pass", "", "pass(example: --pass 'admin,root')")
	crackCmd.Flags().StringVar(&crackOptions.UserFile, "user-file", "", "user file(example: --user-file 'user.txt')")
	crackCmd.Flags().StringVar(&crackOptions.PassFile, "pass-file", "", "pass file(example: --pass-file 'pass.txt')")

	crackCmd.Flags().IntVar(&crackOptions.Threads, "threads", 1, "number of threads")
	crackCmd.Flags().IntVar(&crackOptions.Timeout, "timeout", 10, "timeout in seconds")
	crackCmd.Flags().IntVar(&crackOptions.Delay, "delay", 0, "delay between requests in seconds (0 to disable)")
	crackCmd.Flags().BoolVar(&crackOptions.CrackAll, "crack-all", false, "crack all user:pass")

	rootCmd.AddCommand(crackCmd)
}

var crackCmd = &cobra.Command{
	Use:   "crack",
	Short: "常见服务弱口令爆破",
	Long:  "常见服务弱口令爆破,支持ftp,ssh,wmi,mssql,oracle,mysql,rdp,postgres,redis,memcached,mongodb",
	Run: func(cmd *cobra.Command, args []string) {
		if err := crackOptions.validateOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		if err := crackOptions.configureOptions(); err != nil {
			gologger.Fatal().Msgf("Program exiting: %v", err)
		}

		crackOptions.run()
	},
}

func (o *CrackOptions) validateOptions() error {
	if o.UserFile != "" && !utils.FileExists(o.UserFile) {
		return fmt.Errorf("file %v does not exist", o.UserFile)
	}
	if o.PassFile != "" && !utils.FileExists(o.PassFile) {
		return fmt.Errorf("file %v does not exist", o.PassFile)
	}

	return nil
}

func (o *CrackOptions) configureOptions() error {
	var err error
	if o.User != "" {
		userDict = strings.Split(o.User, ",")
	}
	if o.Pass != "" {
		passDict = strings.Split(o.Pass, ",")
	}
	if o.UserFile != "" {
		if userDict, err = utils.ReadLines(o.UserFile); err != nil {
			return err
		}
	}
	if o.PassFile != "" {
		if passDict, err = utils.ReadLines(o.PassFile); err != nil {
			return err
		}
	}
	// 加载resource资源
	if len(passDict) == 0 {
		if config.Worker.Crack.CommonPass, err = utils.ReadLines(config.Worker.Crack.CommonFile); err != nil {
			return err
		}
		if config.Worker.Crack.TemplatePass, err = utils.ReadLines(config.Worker.Crack.TemplateFile); err != nil {
			return err
		}
	}

	userDict = utils.RemoveDuplicate(userDict)
	passDict = utils.RemoveDuplicate(passDict)

	opt, _ := json.Marshal(o)
	gologger.Debug().Msgf("crackOptions: %v", string(opt))
	gologger.Debug().Msgf("userDict: %v", len(userDict))
	gologger.Debug().Msgf("passDict: %v", len(passDict))

	return nil
}

func (o *CrackOptions) run() {
	options := &crack.Options{
		Threads:      o.Threads,
		Timeout:      o.Timeout,
		Delay:        o.Delay,
		CrackAll:     o.CrackAll,
		UserMap:      config.Worker.Crack.UserMap,
		CommonPass:   config.Worker.Crack.CommonPass,
		TemplatePass: config.Worker.Crack.TemplatePass,
	}
	crackRunner, err := crack.NewRunner(options)
	if err != nil {
		gologger.Error().Msgf("crack.NewRunner() err, %v", err)
		return
	}
	addrs := crack.ParseTargets(targets)
	addrs = crack.FilterModule(addrs, o.Module)
	if len(addrs) == 0 {
		gologger.Error().Msgf("目标为空")
		return
	}
	// 存活探测
	gologger.Info().Msgf("存活探测")
	addrs = crackRunner.CheckAlive(addrs)
	gologger.Info().Msgf("存活数量: %v", len(addrs))
	// 服务爆破
	results := crackRunner.Run(addrs, userDict, passDict)
	if len(results) > 0 {
		gologger.Info().Msgf("爆破成功: %v", len(results))
		for _, result := range results {
			gologger.Print().Msgf("%v -> %v %v", result.Protocol, result.Addr, result.UserPass)
		}
	}
}
