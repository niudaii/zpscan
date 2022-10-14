package webscan

import (
	"strings"
	"sync"
	"time"

	"github.com/imroc/req/v3"
	"github.com/projectdiscovery/gologger"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type Options struct {
	Proxy        string
	Threads      int
	Timeout      int
	Headers      []string
	NoColor      bool
	NoIconhash   bool
	NoWappalyzer bool
	FingerRules  []*FingerRule
}

type Runner struct {
	options          *Options
	reqClient        *req.Client
	wappalyzerClient *wappalyzer.Wappalyze
}

func NewRunner(options *Options) (runner *Runner, err error) {
	runner = &Runner{
		options:   options,
		reqClient: NewReqClient(options.Proxy, options.Timeout, options.Headers),
	}
	if !options.NoWappalyzer {
		runner.wappalyzerClient, err = wappalyzer.New()
		if err != nil {
			return nil, err
		}
	}
	return runner, nil
}

func NewReqClient(proxy string, timeout int, headers []string) *req.Client {
	reqClient := req.C()
	reqClient.GetTLSClientConfig().InsecureSkipVerify = true
	reqClient.SetCommonHeaders(map[string]string{
		"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36",
		"Cookie":     "rememberMe=1", // check shiro
	})
	reqClient.SetRedirectPolicy(req.AlwaysCopyHeaderRedirectPolicy("Cookie"))
	if proxy != "" {
		reqClient.SetProxyURL(proxy)
	}
	var key, value string
	for _, header := range headers {
		tokens := strings.SplitN(header, ":", 2)
		if len(tokens) < 2 {
			continue
		}
		key = strings.TrimSpace(tokens[0])
		value = strings.TrimSpace(tokens[1])
		reqClient.SetCommonHeader(key, value)
	}
	reqClient.SetTimeout(time.Duration(timeout) * time.Second)
	return reqClient
}

func (r *Runner) Run(urls []string) (results Results) {
	// RunTask
	wg := &sync.WaitGroup{}
	rwMutex := sync.RWMutex{}
	taskChan := make(chan string, r.options.Threads)
	for i := 0; i < r.options.Threads; i++ {
		go func() {
			for task := range taskChan {
				resp, err := r.Webinfo(task)
				if err != nil {
					gologger.Debug().Msgf("%v", err)
				} else {
					// 判断蜜罐匹配大量指纹的情况
					if len(resp.Fingers) > 5 {
						gologger.Warning().Msgf("%v 可能为蜜罐", resp.Url)
					} else {
						gologger.Silent().Msgf(FmtResult(resp, r.options.NoColor))
						rwMutex.Lock()
						results = append(results, resp)
						rwMutex.Unlock()
					}
				}
				wg.Done()
			}
		}()
	}

	for _, task := range urls {
		wg.Add(1)
		taskChan <- task
	}
	close(taskChan)
	wg.Wait()

	gologger.Info().Msgf("扫描结束")

	return
}

func (r *Runner) Webinfo(url string) (result *Result, err error) {
	request := r.reqClient.R()
	resp, err := FirstGet(request, url)
	if err != nil {
		return
	}
	// 处理js跳转, 上限3次
	for i := 0; i < 3; i++ {
		jumpurl := Jsjump(resp)
		if jumpurl == "" {
			break
		}
		resp, err = request.Get(jumpurl)
	}
	if err != nil {
		return
	}
	result = &Result{
		Url:           resp.Request.URL.String(),
		StatusCode:    resp.StatusCode,
		ContentLength: len(resp.String()),
		Title:         getTitle(resp),
		Fingers:       r.getFinger(resp),
	}
	if !r.options.NoIconhash {
		result.Favicon, result.IconHash = r.getFavicon(resp)
	}
	if !r.options.NoWappalyzer {
		result.Wappalyzer = r.wappalyzerClient.Fingerprint(resp.Header, resp.Bytes())
	}
	return
}

func FirstGet(r *req.Request, url string) (resp *req.Response, err error) {
	var scheme string
	var flag bool
	if !strings.HasPrefix(url, "http") {
		scheme = "http://"
		resp, err = r.Get(scheme + url)
		if err != nil {
			gologger.Debug().Msgf("r.Get() err, %v", err)
			scheme = "https://"
			flag = true
		} else {
			if strings.Contains(resp.String(), "sent to HTTPS port") || strings.Contains(resp.String(), "This combination of host and port requires TLS") || strings.Contains(resp.String(), "Instead use the HTTPS scheme to") {
				scheme = "https://"
				flag = true
			}
		}
	} else if strings.HasPrefix(url, "http://") {
		resp, err = r.Get(url)
		if err != nil {
			gologger.Debug().Msgf("r.Get() err, %v", err)
			scheme = "https://"
			url = url[7:]
			flag = true
		} else {
			if strings.Contains(resp.String(), "sent to HTTPS port") || strings.Contains(resp.String(), "This combination of host and port requires TLS") || strings.Contains(resp.String(), "Instead use the HTTPS scheme to") {
				scheme = "https://"
				url = url[7:]
				flag = true
			}
		}
	}
	if flag {
		resp, err = r.Get(scheme + url)
	}
	return
}
