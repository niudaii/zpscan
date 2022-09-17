package domainscan

import (
	"fmt"

	"github.com/niudaii/zpscan/internal/utils"

	"github.com/niudaii/domainscan/pkg/domainscan/ksubdomain"
	"github.com/niudaii/domainscan/pkg/domainscan/subfinder"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

type Options struct {
	Layer         int
	SubdomainData []string
	SubnextData   []string
	CdnCnameData  []string
	CdnIpData     []string
	Providers     *runner.Providers
}

type Runner struct {
	options *Options
}

func NewRunner(options *Options) (*Runner, error) {
	return &Runner{
		options: options,
	}, nil
}

type Result struct {
	Domain string
	Ip     string
	Cdn    bool
}

func (r *Runner) Run(domains []string) (results []*Result) {
	for _, domain := range domains {
		results = append(results, r.RunEnumeration(domain)...)
	}
	return
}

func (r *Runner) RunEnumeration(domain string) (results []*Result) {
	gologger.Info().Msgf("当前目标: %v", domain)

	// 被动收集,subfinder
	gologger.Info().Msgf("开始被动收集")
	domains, err := subfinder.Run([]string{domain}, r.options.Providers)
	if err != nil {
		gologger.Error().Msgf("subfinder.Run() err, %v", err)
	}
	// 加入本身这个域名
	domains = append(domains, domain)
	// 判断泛解析
	var isWildcard bool
	if CheckWildcard(domain) {
		isWildcard = true
		gologger.Info().Msgf("存在泛解析: %v", domain)
	} else {
		for _, sub := range r.options.SubdomainData {
			domains = append(domains, sub+"."+domain)
		}
		domains = utils.RemoveDuplicate(domains)
		if r.options.Layer > 1 {
			domainss := domains
			for _, sub2 := range r.options.SubnextData {
				for _, d := range domainss {
					domains = append(domains, sub2+"."+d)
				}
			}
		}
	}
	// 调用ksubdomain进行dns解析
	domains = utils.RemoveDuplicate(domains)
	gologger.Info().Msgf("开始DNS解析: %v", len(domains))
	result, err := ksubdomain.Run(domains)
	if err != nil {
		gologger.Error().Msgf("ksubdomain.Run() err, %v", err)
		return
	}
	domainMap := map[string]bool{}
	gologger.Info().Msgf("ksubdomain: %v", len(result))
	if isWildcard {
		for _, res := range result {
			if domainMap[res.IP] {
				continue
			}
			domainMap[res.IP] = true
			tmpRes := Result{
				Domain: res.Host,
				Ip:     res.IP,
			}
			tmpRes.Cdn = r.CheckCDN(res.IP)
			results = append(results, &tmpRes)
			gologger.Silent().Msgf(fmt.Sprintf("%v => %v => %v", tmpRes.Domain, tmpRes.Ip, tmpRes.Cdn))
		}
	} else {
		for _, res := range result {
			tmpRes := Result{
				Domain: res.Host,
				Ip:     res.IP,
			}
			tmpRes.Cdn = r.CheckCDN(res.IP)
			results = append(results, &tmpRes)
			gologger.Silent().Msgf(fmt.Sprintf("%v => %v => %v", tmpRes.Domain, tmpRes.Ip, tmpRes.Cdn))
		}
	}

	gologger.Info().Msgf("扫描结束")

	return
}
