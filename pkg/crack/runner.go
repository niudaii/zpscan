package crack

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/niudaii/zpscan/internal/utils"
	"github.com/niudaii/zpscan/pkg/crack/plugins"

	"github.com/cheggaaa/pb/v3"
	"github.com/projectdiscovery/gologger"
)

type Options struct {
	Threads  int
	Timeout  int
	Delay    int
	CrackAll bool

	UserMap      map[string][]string
	CommonPass   []string
	TemplatePass []string
}

type Runner struct {
	options *Options
}

func NewRunner(options *Options) (*Runner, error) {
	if len(options.UserMap) == 0 {
		options.UserMap = userMap
	}
	if len(options.CommonPass) == 0 {
		options.CommonPass = commonPass
	}
	if len(options.TemplatePass) == 0 {
		options.TemplatePass = templatePass
	}
	return &Runner{
		options: options,
	}, nil
}

type Result struct {
	Addr     string
	Protocol string
	UserPass string
}

type IpAddr struct {
	Ip       string
	Port     int
	Protocol string
}

func (r *Runner) Run(addrs []*IpAddr, userDict []string, passDict []string) (results []*Result) {
	for _, addr := range addrs {
		results = append(results, r.Crack(addr, userDict, passDict)...)
	}
	return
}

func (r *Runner) Crack(addr *IpAddr, userDict []string, passDict []string) (results []*Result) {
	gologger.Info().Msgf("开始爆破: %v:%v %v", addr.Ip, addr.Port, addr.Protocol)

	var tasks []plugins.Service
	var taskHash string
	taskHashMap := map[string]bool{}
	// GenTask
	if len(userDict) == 0 {
		userDict = r.options.UserMap[addr.Protocol]
	}
	if len(passDict) == 0 {
		passDict = append(passDict, r.options.TemplatePass...)
		passDict = append(passDict, r.options.CommonPass...)
	}
	for _, user := range userDict {
		for _, pass := range passDict {
			// 替换{user}
			pass = strings.ReplaceAll(pass, "{user}", user)
			// 任务去重
			taskHash = utils.Md5(fmt.Sprintf("%v%v%v%v%v", addr.Ip, addr.Port, addr.Protocol, user, pass))
			if taskHashMap[taskHash] {
				continue
			}
			taskHashMap[taskHash] = true
			tasks = append(tasks, plugins.Service{
				Ip:       addr.Ip,
				Port:     addr.Port,
				Protocol: addr.Protocol,
				User:     user,
				Pass:     pass,
				Timeout:  r.options.Timeout,
			})
		}
	}
	// RunTask
	stopHashMap := map[string]bool{}
	mutex := &sync.Mutex{}
	wg := &sync.WaitGroup{}
	taskChan := make(chan plugins.Service, r.options.Threads)
	for i := 0; i < r.options.Threads; i++ {
		go func() {
			for task := range taskChan {
				addrStr := fmt.Sprintf("%v:%v", addr.Ip, addr.Port)
				userPass := fmt.Sprintf("%v:%v", task.User, task.Pass)
				addrHash := utils.Md5(addrStr)
				// 判断是否已经停止爆破
				mutex.Lock()
				if stopHashMap[addrHash] {
					mutex.Unlock()
					wg.Done()
					continue
				}
				mutex.Unlock()
				gologger.Debug().Msgf("[trying] %v", userPass)
				scanFunc := plugins.ScanFuncMap[task.Protocol]
				resp := scanFunc(&task)
				switch resp {
				case plugins.CrackSuccess:
					if !r.options.CrackAll {
						mutex.Lock()
						stopHashMap[addrHash] = true
						mutex.Unlock()
					}
					gologger.Silent().Msgf("%v -> %v %v", addr.Protocol, addrStr, userPass)
					results = append(results, &Result{
						Addr:     addrStr,
						Protocol: addr.Protocol,
						UserPass: userPass,
					})
				case plugins.CrackError:
					mutex.Lock()
					stopHashMap[addrHash] = true
					mutex.Unlock()
				case plugins.CrackFail:
				}
				if r.options.Delay > 0 {
					time.Sleep(time.Duration(r.options.Delay) * time.Second)
				}
				wg.Done()
			}
		}()
	}

	bar := pb.StartNew(len(tasks))
	for _, task := range tasks {
		wg.Add(1)
		taskChan <- task
		bar.Increment()
	}
	close(taskChan)
	wg.Wait()
	bar.Finish()

	gologger.Info().Msgf("爆破结束")

	return
}
