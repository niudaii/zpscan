package webscan

import (
	"github.com/imroc/req/v3"
	"github.com/projectdiscovery/gologger"
	"sync"
	"time"
)

// CheckAlive HTTP存活扫描
func CheckAlive(urls []string, timeout, threads int, proxy string) (results []string) {
	if len(urls) == 0 {
		return
	}
	gologger.Info().Msgf("开始HTTP探活: %v", len(urls))
	client := req.C()
	client.SetTimeout(time.Duration(timeout) * time.Second)
	client.GetTLSClientConfig().InsecureSkipVerify = true
	if proxy != "" {
		client.SetProxyURL(proxy)
	}
	// RunTask
	wg := &sync.WaitGroup{}
	mutex := sync.Mutex{}
	taskChan := make(chan string, threads)
	for i := 0; i < threads; i++ {
		go func() {
			for task := range taskChan {
				resp, err := client.R().Get("http://" + task)
				if err == nil {
					mutex.Lock()
					results = append(results, resp.Request.URL.String())
					mutex.Unlock()
				} else {
					gologger.Debug().Msgf("%v", err)
					resp, err = client.R().Get("https://" + task)
					if err == nil {
						mutex.Lock()
						results = append(results, resp.Request.URL.String())
						mutex.Unlock()
					} else {
						gologger.Debug().Msgf("%v", err)
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

	gologger.Info().Msgf("HTTP探活结束")
	return
}
