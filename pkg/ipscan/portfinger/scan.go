package portfinger

import (
	"context"
	"github.com/projectdiscovery/gologger"
	"golang.org/x/net/proxy"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	Scanner *NmapProbe
	Threads int
	Proxy   string
}

func NewEngine(threads int, proxy string, scanner *NmapProbe) (*Engine, error) {
	return &Engine{
		Threads: threads,
		Scanner: scanner,
		Proxy:   proxy,
	}, nil
}

// Directive 定义探针probe说明字段
type Directive struct {
	DirectiveName string
	Flag          string
	Delimiter     string
	DirectiveStr  string
}

// Extras 探针匹配成功解析数据
type Extras struct {
	ServiceName     string
	VendorProduct   string
	Version         string
	Info            string
	Hostname        string
	OperatingSystem string
	DeviceType      string
	CPE             string
	Sign            string
}

type Address struct {
	IP   string
	Port string
}

func (e *Engine) Run(targets map[string]map[int]struct{}) []*Result {
	var results []*Result
	// 并发任务
	wg := &sync.WaitGroup{}
	taskChan := make(chan Address, e.Threads)
	for i := 0; i < e.Threads; i++ {
		go func() {
			for task := range taskChan {
				resp := e.Scanner.ScanWithProbe(task.IP, task.Port, e.Proxy, 5)
				if resp.ServiceName != "" {
					gologger.Silent().Msgf("result: %v", resp)
					results = append(results, resp)
				}
				wg.Done()
			}
		}()
	}

	// 往chan发送目标
	for ip, ports := range targets {
		for port := range ports {
			addr := Address{
				IP:   ip,
				Port: strconv.Itoa(port),
			}
			wg.Add(1)
			taskChan <- addr
		}
	}
	wg.Wait()
	close(taskChan)
	return results
}

// DecodePattern 解析探针数据包
func DecodePattern(s string) ([]byte, error) {
	sByteOrigin := []byte(s)
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			if isReChar(byteNum) {
				replace = []byte{'\\', uint8(byteNum)}
			} else {
				replace = []byte{uint8(byteNum)}
			}
		}
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  []byte{0x07}, // \a
				102: []byte{0x0c}, // \f
				116: []byte{0x09}, // \t
				110: []byte{0x0a}, // \n
				114: []byte{0x0d}, // \r
				118: []byte{0x0b}, // \v
			}
			replace = structCodeMap[int(match[1])]
		}
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		var replace []byte
		if isOtherEscapeCode(match) {
			replace = match
		} else {
			replace = match
		}
		return replace
	})
	return sByteDec2, nil
}

func isReChar(n int64) bool {
	reChars := `.*?+{}()^$|\`
	for _, char := range reChars {
		if n == int64(char) {
			return true
		}
	}
	return false
}

// DecodeData socket发送探测数据包编码
func DecodeData(s string) ([]byte, error) {
	sByteOrigin := []byte(s)
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			replace = []byte{uint8(byteNum)}
		}
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  []byte{0x07}, // \a
				102: []byte{0x0c}, // \f
				116: []byte{0x09}, // \t
				110: []byte{0x0a}, // \n
				114: []byte{0x0d}, // \r
				118: []byte{0x0b}, // \v
			}
			replace = structCodeMap[int(match[1])]
		}
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		var replace []byte
		if isOtherEscapeCode(match) {
			replace = match
		} else {
			replace = match
		}
		return replace
	})
	return sByteDec2, nil
}

func isHexCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	return matchRe.Match(b)
}

func isOctalCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[0-7]{1,3}`)
	return matchRe.Match(b)
}

func isStructCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[aftnrv]`)
	return matchRe.Match(b)
}

func isOtherEscapeCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[^\\]`)
	return matchRe.Match(b)
}

// response正则判断
func (N *NmapProbe) regxRespone(response []byte, matchtmp []*Match, Fallback string) (bool, *Extras) {
	extras := Extras{}
	if len(response) > 0 {
		for _, match := range matchtmp { // 循环匹配该协议中的正则表达式
			matched := match.MatchPattern(response)
			if matched && !match.IsSoft {
				extras = match.ParseVersionInfo(response)
				extras.ServiceName = match.Service
				return true, &extras
			}
		}
		if _, ok := N.ProbesMapKName[Fallback]; ok { // 进行贪婪匹配
			fbProbe := N.ProbesMapKName[Fallback]
			for _, match := range fbProbe.Matchs {
				matched := match.MatchPattern(response)
				if matched && !match.IsSoft {
					extras = match.ParseVersionInfo(response)
					extras.ServiceName = match.Service
					return true, &extras
				}
			}
		}
	}
	return false, &extras
}

// 正则匹配respone内容
func (m *Match) MatchPattern(response []byte) (matched bool) {
	responseStr := string([]rune(string(response)))
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)
	if len(foundItems) > 0 {
		matched = true
		return
	}
	return false
}

// ParseVersionInfo 正则匹配respone成功，取出相应的内容
func (m *Match) ParseVersionInfo(response []byte) Extras {
	var extras = Extras{}

	responseStr := string([]rune(string(response)))
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)

	versionInfo := m.VersionInfo
	foundItems = foundItems[1:]
	for index, value := range foundItems {
		dollarName := "$" + strconv.Itoa(index+1)
		versionInfo = strings.Replace(versionInfo, dollarName, value, -1)
	}

	v := versionInfo
	if strings.Contains(v, " p/") {
		regex := regexp.MustCompile(`p/([^/]*)/`)
		vendorProductName := regex.FindStringSubmatch(v)
		extras.VendorProduct = vendorProductName[1]
	}
	if strings.Contains(v, " p|") {
		regex := regexp.MustCompile(`p|([^|]*)|`)
		vendorProductName := regex.FindStringSubmatch(v)
		extras.VendorProduct = vendorProductName[1]
	}
	if strings.Contains(v, " v/") {
		regex := regexp.MustCompile(`v/([^/]*)/`)
		version := regex.FindStringSubmatch(v)
		extras.Version = version[1]
	}
	if strings.Contains(v, " v|") {
		regex := regexp.MustCompile(`v|([^|]*)|`)
		version := regex.FindStringSubmatch(v)
		extras.Version = version[1]
	}
	if strings.Contains(v, " i/") {
		regex := regexp.MustCompile(`i/([^/]*)/`)
		info := regex.FindStringSubmatch(v)
		extras.Info = info[1]
	}
	if strings.Contains(v, " i|") {
		regex := regexp.MustCompile(`i|([^|]*)|`)
		info := regex.FindStringSubmatch(v)
		extras.Info = info[1]
	}
	if strings.Contains(v, " h/") {
		regex := regexp.MustCompile(`h/([^/]*)/`)
		hostname := regex.FindStringSubmatch(v)
		extras.Hostname = hostname[1]
	}
	if strings.Contains(v, " h|") {
		regex := regexp.MustCompile(`h|([^|]*)|`)
		hostname := regex.FindStringSubmatch(v)
		extras.Hostname = hostname[1]
	}
	if strings.Contains(v, " o/") {
		regex := regexp.MustCompile(`o/([^/]*)/`)
		operatingSystem := regex.FindStringSubmatch(v)
		extras.OperatingSystem = operatingSystem[1]
	}
	if strings.Contains(v, " o|") {
		regex := regexp.MustCompile(`o|([^|]*)|`)
		operatingSystem := regex.FindStringSubmatch(v)
		extras.OperatingSystem = operatingSystem[1]
	}
	if strings.Contains(v, " d/") {
		regex := regexp.MustCompile(`d/([^/]*)/`)
		deviceType := regex.FindStringSubmatch(v)
		extras.DeviceType = deviceType[1]
	}
	if strings.Contains(v, " d|") {
		regex := regexp.MustCompile(`d|([^|]*)|`)
		deviceType := regex.FindStringSubmatch(v)
		extras.DeviceType = deviceType[1]
	}
	if strings.Contains(v, " cpe:/") {
		regex := regexp.MustCompile(`cpe:/([^/]*)/`)
		cpeName := regex.FindStringSubmatch(v)
		if len(cpeName) > 1 {
			extras.CPE = cpeName[1]
		} else {
			extras.CPE = cpeName[0]
		}
	}
	if strings.Contains(v, " cpe:|") {
		regex := regexp.MustCompile(`cpe:|([^|]*)|`)
		cpeName := regex.FindStringSubmatch(v)
		if len(cpeName) > 1 {
			extras.CPE = cpeName[1]
		} else {
			extras.CPE = cpeName[0]
		}
	}
	return extras
}

// 进行socket连接发送数据
func (N *NmapProbe) grabResponse(addr, proxyAddr string, Indexes, SocketTimeout int) ([]byte, error) {
	var response []byte // 保存响应的结果
	dialer, err := proxy.SOCKS5("tcp", proxyAddr,
		nil,
		nil,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	conn, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", addr)
	if err != nil { // 连接端口失败
		return nil, err
	}
	gologger.Debug().Msgf("Index.Data: %v", string(N.Probes[Indexes].Data))

	if len(N.Probes[Indexes].Data) > 0 { // 发送指纹探测数据
		err := conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(int64(SocketTimeout))))
		if err != nil {
			return nil, err
		}
		_, errWrite := conn.Write(N.Probes[Indexes].Data)
		if errWrite != nil {
			return nil, errWrite
		}
	}

	err = conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(int64(SocketTimeout))))
	if err != nil {
		return nil, err
	}
	for {
		buff := make([]byte, 1024)
		n, errRead := conn.Read(buff)
		if errRead != nil {
			if len(response) > 0 {
				break
			} else {
				return nil, errRead
			}
		}
		if n > 0 {
			response = append(response, buff[:n]...)
		}
	}
	return response, nil
}

// ScanWithProbe 单端口 指纹探测
func (N *NmapProbe) ScanWithProbe(host, port, proxyAddr string, SocketTimeout int) *Result {
	var defaultProbe []int // 保存默认端口对应的协议索引
	var oneProbe []int     // 保存优先级为一对应的协议索引
	var sixProbe []int     // 保存优先级小于6对应的协议索引
	var nineProbe []int    // 保存剩余对应的协议索引
	var excludeIndex []int // 保存排除的协议索引

	for i := 0; i < len(N.Probes); i++ {
		// 组合默认端口对应协议
		for _, v := range N.Probes[i].Ports {
			_, ok := v[port]
			if ok {
				defaultProbe = append(defaultProbe, i)
				excludeIndex = append(excludeIndex, i)
				break
			}
		}
		// 组合优先级为一的协议
		if N.Probes[i].Rarity == 1 && !IsExclude(excludeIndex, i) {
			oneProbe = append(oneProbe, i)
		}
		// 组合优先级小于6的协议
		if N.Probes[i].Rarity != 1 && N.Probes[i].Rarity < 6 && !IsExclude(excludeIndex, i) {
			sixProbe = append(sixProbe, i)
		}
		// 组合剩余的协议
		if N.Probes[i].Rarity >= 6 && !IsExclude(excludeIndex, i) {
			nineProbe = append(nineProbe, i)
		}
	}

	// 优先并发探测默认端口的协议
	if len(defaultProbe) > 0 {
		wg := sync.WaitGroup{}
		chanResult := make(chan *Result, len(defaultProbe))
		for _, i := range defaultProbe {
			wg.Add(1)
			go func(v int) {
				defer wg.Done()
				N.ResultSocket(GetAddress(host, port), proxyAddr, v, SocketTimeout, chanResult)
			}(i)
		}
		wg.Wait()
		close(chanResult)
		for resp := range chanResult {
			gologger.Debug().Msgf("[+] 默认端口指纹获取成功:%s:%s %s", host, port, resp.ServiceName)
			return resp
		}
	}

	// 并发探测等级为1的协议
	if len(oneProbe) > 0 {
		gologger.Debug().Msg("并发探测等级为1的协议")
		wg := sync.WaitGroup{}
		chanResult := make(chan *Result, len(oneProbe))
		for _, i := range oneProbe {
			wg.Add(1)
			go func(v int) {
				defer wg.Done()
				N.ResultSocket(GetAddress(host, port), proxyAddr, v, SocketTimeout, chanResult)
			}(i)
		}
		wg.Wait()
		close(chanResult)
		for resp := range chanResult {
			gologger.Debug().Msgf("[+] 级别1指纹获取成功:%s:%s %s\n", host, port, resp.ServiceName)
			return resp
		}
	}

	// 并发探测等级小于6的协议
	if len(sixProbe) > 0 {
		gologger.Debug().Msg("并发探测等级小于6的协议")
		wg := sync.WaitGroup{}
		chanResult := make(chan *Result, len(sixProbe))
		for _, i := range sixProbe {
			wg.Add(1)
			go func(v int) {
				defer wg.Done()
				N.ResultSocket(GetAddress(host, port), proxyAddr, v, SocketTimeout, chanResult)
			}(i)
		}
		wg.Wait()
		close(chanResult)
		for resp := range chanResult {
			gologger.Debug().Msgf("[+] 级别<6指纹获取成功:%s:%s %s", host, port, resp.ServiceName)
			return resp
		}
	}

	// 并发探测剩下等级的协议
	if len(nineProbe) > 0 {
		wg := sync.WaitGroup{}
		chanResult := make(chan *Result, len(nineProbe))
		for _, i := range nineProbe {
			wg.Add(1)
			go func(v int) {
				defer wg.Done()
				N.ResultSocket(GetAddress(host, port), proxyAddr, v, SocketTimeout, chanResult)
			}(i)
		}
		wg.Wait()
		close(chanResult)
		for resp := range chanResult {
			gologger.Debug().Msgf("[+] 级别<9指纹获取成功:%s:%s %s", host, port, resp.ServiceName)
			return resp
		}
	}

	// 若未识别出指纹，则按照默认端口对应的指纹返回
	gologger.Debug().Msgf("[-] 未知服务:%s:%s", host, port)
	Resulttmp := Result{}
	Resulttmp.Addr = GetAddress(host, port)
	return &Resulttmp
}

// 识别端口服务指纹
func (N *NmapProbe) ResultSocket(address, proxyAddr string, Indexes, SocketTimeout int, ResultChan chan *Result) {
	//gologger.Debug().Msgf("调用ResultSocket函数 %v %d \n", address, Indexes)
	responeData, err := N.grabResponse(address, proxyAddr, Indexes, SocketTimeout)
	if err != nil { // 端口发送指纹失败
		return
	}
	//gologger.Debug().Msgf("socket 返回 responseData %v \n", string(responeData))
	ok, extras := N.regxRespone(responeData, N.Probes[Indexes].Matchs, N.Probes[Indexes].Fallback)
	if !ok { // 指纹识别失败
		return
	}
	ResultChan <- &Result{
		Addr:          address,
		ServiceName:   extras.ServiceName,
		ProbeName:     N.Probes[Indexes].Name,
		VendorProduct: extras.VendorProduct,
		Version:       extras.Version,
	}
}

// GetAddress 组合host
func GetAddress(ip, port string) string {
	return ip + ":" + port
}

func IsExclude(m []int, value int) bool {
	for _, v := range m {
		if v == value {
			return true
		}
	}
	return false
}
