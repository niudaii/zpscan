package config

import (
	"github.com/niudaii/zpscan/pkg/pocscan/goby"
	"github.com/niudaii/zpscan/pkg/pocscan/nuclei"
	"github.com/niudaii/zpscan/pkg/pocscan/xray"
	"log"

	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/ipscan/portfinger"
	"github.com/niudaii/zpscan/pkg/ipscan/qqwry"
	"github.com/niudaii/zpscan/pkg/webscan"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Domainscan Domainscan `yaml:"domainscan"`
	Ipscan     Ipscan     `yaml:"ipscan"`
	Crack      Crack      `yaml:"crack"`
	Webscan    Webscan    `yaml:"webscan"`
	Dirscan    Dirscan    `yaml:"dirscan"`
	Pocscan    Pocscan    `yaml:"pocscan"`
}

type Domainscan struct {
	SubdomainFile string `yaml:"subdomain-file"`
	SubnextFile   string `yaml:"subnext-file"`
	CdnCnameFile  string `yaml:"cdn-cname-file"`
	CdnIpFile     string `yaml:"cdn-ip-file"`
	ProviderFile  string `yaml:"provider-file"`
	FofaEmail     string `yaml:"fofa-email"`
	FofaKey       string `yaml:"fofa-key"`
	SubdomainData []string
	SubnextData   []string
	CdnCnameData  []string
	CdnIpData     []string
	Providers     *runner.Providers
}

type Ipscan struct {
	QqwryFile string `yaml:"qqwry-file"`
	NmapFile  string `yaml:"nmap-file"`
	Qqwry     *qqwry.QQwry
	NmapProbe *portfinger.NmapProbe
}

type Crack struct {
	UserMap      map[string][]string `yaml:"user-map"`
	CommonFile   string              `yaml:"common-file"`
	TemplateFile string              `yaml:"template-file"`
	CommonPass   []string
	TemplatePass []string
	UserDict     []string
	PassDict     []string
}

type Webscan struct {
	FingerFile  string `yaml:"finger-file"`
	UpdateUrl   string `yaml:"update-url"`
	FingerRules []*webscan.FingerRule
}

type Dirscan struct {
	BackupFile   string   `yaml:"backup-file"`
	BackupSuffix []string `yaml:"backup-suffix"`
	CatalogFile  string   `yaml:"catalog-file"`
	ApiFile      string   `yaml:"api-file"`
	LeakFile     string   `yaml:"leak-file"`
	VulnFile     string   `yaml:"vuln-file"`
	CommonFile   string   `yaml:"common-file"`
	DirMap       map[string][]string
}

type Pocscan struct {
	GobyPocDir   string `yaml:"goby-poc-dir"`
	XrayPocDir   string `yaml:"xray-poc-dir"`
	NucleiPocDir string `yaml:"nuclei-poc-dir"`
	GobyPocs     []*goby.Poc
	XrayPocs     []*xray.Poc
	NucleiPocs   []*nuclei.Poc
}

var Worker Config

const configFile = "config.yaml"

func init() {
	bytes, err := utils.ReadFile(configFile)
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(bytes, &Worker)
	if err != nil {
		log.Fatal(err)
	}
}
