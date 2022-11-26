package dirscan

import (
	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/webscan"
	"strings"
	"sync"

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
		reqClient: utils.NewReqClient(options.Proxy, options.Timeout, options.Headers),
	}, nil
}

type Input struct {
	Target string
	Dirs   []string
}

var contentTypes = []string{".zip", ".7z", ".rar", ".tar", ".txt", ".tar.gz", ".tgz", ".bak", ".swp", ".jar", ".war", ".sql"}
var contentTypeMap = map[string]string{
	".zip":    "application/zip",
	".7z":     "application/x-7z-compressed",
	".rar":    "application/x-rar-compressed",
	".tar":    "application/x-tar",
	".txt":    "text/plain",
	".tar.gz": "application/gzip",
	".tgz":    "application/x-tar",
	".bak":    "application/octet-stream",
	".swp":    "application/octet-stream",
	".jar":    "application/java-archive",
	".war":    "application/octet-stream",
	".sql":    "application/x-sql",
}

func (r *Runner) Run(inputs []*Input) (results Results) {
	for _, input := range inputs {
		results = append(results, r.Dirscan(input)...)
	}
	return
}

func (r *Runner) Dirscan(input *Input) (results Results) {
	gologger.Info().Msgf("开始扫描: %v", input.Target)
	// 存活检测
	resp, err := webscan.FirstGet(r.reqClient.R(), input.Target)
	if err != nil {
		gologger.Error().Msgf("%v", err)
		return
	}
	url := resp.Request.URL.String()
	tasks := make([]string, 0)
	url = strings.TrimSuffix(url, "/")
	for _, dir := range input.Dirs {
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
				var result *Result
				result, err = r.Req(task)
				if err != nil {
					gologger.Debug().Msgf("%v", err)
				} else {
					if result.ContentLength != 0 && utils.HasInt(r.options.MatchStatus, result.StatusCode) {
						flag := true
						if suffix, ok := utils.SuffixStr(contentTypes, result.Url); ok {
							if result.ContentType != contentTypeMap[suffix] {
								flag = false
							}
						}
						if flag {
							gologger.Silent().Msgf("%v [%v] [%v]", result.Url, result.StatusCode, result.ContentLength)
							mutex.Lock()
							respMap[result.ContentLength] += 1
							tmpResults = append(tmpResults, result)
							mutex.Unlock()
						}
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
		ContentType:   resp.GetContentType(),
	}
	return
}
