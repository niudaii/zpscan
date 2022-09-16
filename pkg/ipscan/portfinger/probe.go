package portfinger

import (
	_ "embed"
	"regexp"
	"strconv"
	"strings"

	"github.com/projectdiscovery/gologger"
)

// 对nmap指纹库进行解析

type NmapProbe struct {
	Probes         []*Probe
	ProbesMapKName map[string]*Probe // 以探针名为key对应Probe
}

type Probe struct {
	Name     string              // 探针名称
	Ports    []map[string]string // 该探针默认端口
	Data     []byte              // socket发送的数据
	Fallback string              // 如果探针匹配项没有匹配到，则使用Fallback指定的探针作为备用
	Matchs   []*Match            // 正则协议内容
	Rarity   int                 // 指纹探测等级
}

type Match struct {
	IsSoft          bool
	Service         string
	Pattern         string
	VersionInfo     string
	PatternCompiled *regexp.Regexp
}

// Init nmap指纹库初始化
func (N *NmapProbe) Init(nmapData []byte) error {
	nmapStr := string(nmapData)
	N.parseProbesFromContent(&nmapStr) // 解析nmap指纹库
	N.parseProbesToMapKName()

	return nil
}

// Count 统计指纹库中正则条数
func (N *NmapProbe) Count() int {
	count := 0
	for _, probe := range N.Probes {
		count += len(probe.Matchs)
	}
	return count
}

// 将probe变成key-value形式, 方便后面进行备用探针匹配
func (N *NmapProbe) parseProbesToMapKName() {
	var probesMap = map[string]*Probe{}
	for _, probe := range N.Probes {
		probesMap[probe.Name] = probe
	}
	N.ProbesMapKName = probesMap
}

// 解析nmap指纹库
func (N *NmapProbe) parseProbesFromContent(content *string) {
	var probes []*Probe
	var lines []string
	linesTemp := strings.Split(*content, "\n")

	// 过滤掉规则文件中的注释和空行
	for _, lineTemp := range linesTemp {
		lineTemp = strings.TrimSpace(lineTemp)
		if lineTemp == "" || strings.HasPrefix(lineTemp, "#") {
			continue
		}
		lines = append(lines, lineTemp)
	}
	if len(lines) == 0 {
		gologger.Debug().Msgf("[-] [端口扫描] nmap指纹库数据为空\n")
	}

	// 判断指纹库中是否只有一个Exclude标识符
	c := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "Exclude ") {
			c += 1
		}
		if c > 1 {
			gologger.Debug().Msgf("[-] [端口扫描] nmap指纹库格式错误，只能有一个Exclude标识符，且该标识符应该在首行")
		}
	}

	// 判断nmap指纹库首行格式
	l := lines[0]
	if !(strings.HasPrefix(l, "Exclude ") || strings.HasPrefix(l, "Probe ")) {
		gologger.Debug().Msgf("[-] [端口扫描] nmap指纹库解析失败，首行应该由Probe或Exclude标识符开始")
	}

	// 去除首行Exclude标识符
	if c == 1 {
		lines = lines[1:]
	}

	// 剩下的都是有效的指纹库数据，重新拼接数据
	content1 := strings.Join(lines, "\n")
	content1 = "\n" + content1
	probeParts := strings.Split(content1, "\nProbe") // 以探针Probe标识进行分割
	// 为何只取第一部分
	probeParts = probeParts[1:]

	for _, probePart := range probeParts {
		probe := Probe{}
		probe.fromString(&probePart)
		probes = append(probes, &probe)
	}
	N.Probes = probes
}

// 解析每段探针probe标识符数据
func (p *Probe) fromString(data *string) {
	data1 := strings.TrimSpace(*data)
	lines := strings.Split(data1, "\n")
	probeStr := lines[0]

	// 解析探针Probe开头信息
	p.parseProbeInfo(probeStr)

	var matchs []*Match
	for _, line := range lines {
		if strings.HasPrefix(line, "match ") {
			match, err := p.getMatch(line)
			if err != nil {
				continue
			}
			matchs = append(matchs, &match)
		} else if strings.HasPrefix(line, "softmatch ") {
			softMatch, err := p.getSoftMatch(line)
			if err != nil {
				continue
			}
			matchs = append(matchs, &softMatch)
		} else if strings.HasPrefix(line, "ports ") {
			p.parsePorts(line)
		} else if strings.HasPrefix(line, "fallback ") {
			p.parseFallback(line)
		} else if strings.HasPrefix(line, "rarity ") {
			p.parseRarity(line)
		}
	}
	p.Matchs = matchs
}

// 解析探针Probe开头信息
func (p *Probe) parseProbeInfo(probeStr string) {
	proto := probeStr[:4]
	other := probeStr[4:]
	if !(proto == "TCP " || proto == "UDP ") {
		gologger.Debug().Msgf("[-] [端口扫描] 解析nmap指纹库失败，protocol字段必须为TCP或UDP")
	}
	if len(other) == 0 {
		gologger.Debug().Msgf("[-] [端口扫描] 解析nmap指纹库失败，探测名称描述字段名为空")
	}
	directive := p.getDirectiveSyntax(other)
	p.Name = directive.DirectiveName
	dataList := strings.Split(directive.DirectiveStr, directive.Delimiter)
	if len(dataList) > 0 {
		dataByte, err := DecodeData(dataList[0])
		if err != nil {
			gologger.Debug().Msgf("[-] [端口扫描] nmap指纹库编码发送包失败[%s]:  %s\n", dataList[0], err)
		} else {
			p.Data = dataByte
		}
	}
}

// 解析 Probe 说明字段  Probe TCP RTSPRequest q|OPTIONS / RTSP/1.0\r\n\r\n|
func (p *Probe) getDirectiveSyntax(data string) (directive Directive) {
	directive = Directive{}
	blankIndex := strings.Index(data, " ")
	directiveName := data[:blankIndex]
	Flag := data[blankIndex+1 : blankIndex+2]
	delimiter := data[blankIndex+2 : blankIndex+3]
	directiveStr := data[blankIndex+3:]
	directive.DirectiveName = directiveName
	directive.Flag = Flag
	directive.Delimiter = delimiter
	directive.DirectiveStr = directiveStr
	return directive
}

func (p *Probe) getMatch(data string) (match Match, err error) {
	match = Match{}

	matchText := data[len("match")+1:]
	directive := p.getDirectiveSyntax(matchText)

	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)

	pattern, versionInfo := textSplited[0], strings.Join(textSplited[1:], "")

	patternUnescaped, _ := DecodePattern(pattern)
	patternUnescapedStr := string(patternUnescaped)
	patternCompiled, ok := regexp.Compile(patternUnescapedStr)
	if ok != nil {
		return match, ok
	}

	match.Service = directive.DirectiveName
	match.Pattern = pattern
	match.PatternCompiled = patternCompiled
	match.VersionInfo = versionInfo

	return match, nil
}

func (p *Probe) getSoftMatch(data string) (softMatch Match, err error) {
	softMatch = Match{IsSoft: true}

	matchText := data[len("softmatch")+1:]
	directive := p.getDirectiveSyntax(matchText)

	textSplited := strings.Split(directive.DirectiveStr, directive.Delimiter)

	pattern, versionInfo := textSplited[0], strings.Join(textSplited[1:], "")
	patternUnescaped, _ := DecodePattern(pattern)
	patternUnescapedStr := string(patternUnescaped)
	patternCompiled, ok := regexp.Compile(patternUnescapedStr)
	if ok != nil {
		return softMatch, ok
	}

	softMatch.Service = directive.DirectiveName
	softMatch.Pattern = pattern
	softMatch.PatternCompiled = patternCompiled
	softMatch.VersionInfo = versionInfo

	return softMatch, nil
}

// 解析协议的默认端口
func (p *Probe) parsePorts(data string) {
	data1 := strings.Replace(data, "ports ", "", -1)
	if strings.Contains(data1, ",") { // 是否为多个端口
		strlist := strings.Split(data1, ",")
		for _, v := range strlist {
			p.Ports = append(p.Ports, map[string]string{v: ""})
		}
	} else {
		p.Ports = []map[string]string{{data1: ""}}
	}
}

func (p *Probe) parseFallback(data string) {
	p.Fallback = data[len("fallback")+1:]
}

func (p *Probe) parseRarity(data string) {
	p.Rarity, _ = strconv.Atoi(data[len("rarity")+1:])
}
