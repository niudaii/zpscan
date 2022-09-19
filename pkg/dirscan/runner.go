package dirscan

import (
	"strings"
	"sync"
	"time"

	"github.com/niudaii/zpscan/internal/utils"

	"github.com/imroc/req/v3"
	"github.com/projectdiscovery/gologger"
)

type Options struct {
	Proxy   string
	Threads int
	Timeout int
	Headers []string

	MaxMatched  int
	MatchStatus []int
}

type Runner struct {
	options   *Options
	reqClient *req.Client
}

func NewRunner(options *Options) (*Runner, error) {
	return &Runner{
		options:   options,
		reqClient: NewReqClient(options.Proxy, options.Timeout, options.Headers),
	}, nil
}

func NewReqClient(proxy string, timeout int, headers []string) *req.Client {
	reqClient := req.C()
	reqClient.GetTLSClientConfig().InsecureSkipVerify = true
	reqClient.SetCommonHeaders(map[string]string{
		"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36",
	})
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

func (r *Runner) Run(urls []string, dirData []string) (results Results) {
	for _, url := range urls {
		results = append(results, r.Dirscan(url, dirData)...)
	}
	return
}

func (r *Runner) Dirscan(url string, dirData []string) (results Results) {
	gologger.Info().Msgf("开始扫描: %v", url)
	// 存活检测
	_, err := r.reqClient.R().Get(url)
	if err != nil {
		gologger.Error().Msgf("%v", err)
		return
	}
	tasks := make([]string, 0)
	if strings.HasSuffix(url, "/") {
		url = url[:len(url)-1]
	}
	for _, dir := range dirData {
		if !strings.HasPrefix(dir, "/") {
			dir = "/" + dir
		}
		tasks = append(tasks, url+dir)
	}
	// RunTask
	mutex := &sync.Mutex{}
	wg := &sync.WaitGroup{}
	taskChan := make(chan string, r.options.Threads)
	respMap := map[int]int{}
	var tmpResults Results
	for i := 0; i < r.options.Threads; i++ {
		go func() {
			for task := range taskChan {
				resp, err := r.Req(task)
				if err != nil {
					gologger.Debug().Msgf("%v", err)
				} else {
					if resp.ContentLength != 0 && utils.IsExclude(r.options.MatchStatus, resp.StatusCode) {
						mutex.Lock()
						respMap[resp.StatusCode] += 1
						tmpResults = append(tmpResults, resp)
						mutex.Unlock()
						gologger.Silent().Msgf("%v [%v] [%v]", resp.Url, resp.StatusCode, resp.ContentLength)
					}
				}
				wg.Done()
			}
		}()
	}

	for _, task := range tasks {
		wg.Add(1)
		taskChan <- task
	}
	close(taskChan)
	wg.Wait()

	for _, result := range tmpResults {
		if respMap[result.ContentLength] < r.options.MaxMatched {
			results = append(results, &Result{
				Url:           result.Url,
				StatusCode:    result.StatusCode,
				ContentLength: result.ContentLength,
			})
		}
	}

	gologger.Info().Msgf("扫描结束")

	return
}

func (r *Runner) Req(url string) (result *Result, err error) {
	request := r.reqClient.R()
	resp, err := request.Get(url)
	if err != nil {
		return
	}
	result = &Result{
		Url:           resp.Request.URL.String(),
		StatusCode:    resp.StatusCode,
		ContentLength: len(resp.String()),
	}
	return
}
