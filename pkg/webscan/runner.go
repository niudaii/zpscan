package webscan

import (
	"github.com/imroc/req/v3"
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/projectdiscovery/gologger"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"strings"
	"sync"
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
		reqClient: utils.NewReqClient(options.Proxy, options.Timeout, options.Headers),
	}
	runner.reqClient.SetCommonHeader("Cookie", "rememberMe=1") // check shiro
	if !options.NoWappalyzer {
		runner.wappalyzerClient, err = wappalyzer.New()
		if err != nil {
			return nil, err
		}
	}
	return runner, nil
}

func (r *Runner) Run(urls []string) (results Results) {
	// RunTask
	wg := &sync.WaitGroup{}
	mutex := sync.Mutex{}
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
						mutex.Lock()
						results = append(results, resp)
						mutex.Unlock()
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
	resp, err := FirstGet(r.reqClient, url)
	if err != nil {
		return
	}
	// 处理js跳转, 上限3次
	for i := 0; i < 3; i++ {
		jumpurl := Jsjump(resp)
		if jumpurl == "" {
			break
		}
		resp, err = r.reqClient.R().Get(jumpurl)
	}
	if err != nil {
		return
	}
	result = &Result{
		Url:           resp.Request.URL.Scheme + "://" + resp.Request.URL.Host,
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
	gologger.Silent().Msgf(FmtResult(result, r.options.NoColor))
	return
}

func FirstGet(client *req.Client, url string) (resp *req.Response, err error) {
	request := client.R()
	var scheme string
	var flag bool
	if !strings.HasPrefix(url, "http") {
		scheme = "http://"
		resp, err = request.Get(scheme + url)
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
		resp, err = request.Get(url)
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
	} else {
		flag = true
	}
	if flag {
		resp, err = request.Get(scheme + url)
	}
	return
}
