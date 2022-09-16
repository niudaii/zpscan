package crack

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cheggaaa/pb/v3"
)

// CheckAlive 存活检测
func (r *Runner) CheckAlive(addrs []*IpAddr) (results []*IpAddr) {
	// RunTask
	mutex := &sync.Mutex{}
	wg := &sync.WaitGroup{}
	taskChan := make(chan *IpAddr, r.options.Threads)
	for i := 0; i < r.options.Threads; i++ {
		go func() {
			for task := range taskChan {
				if r.conn(task) {
					mutex.Lock()
					results = append(results, task)
					mutex.Unlock()
				}
				wg.Done()
			}
		}()
	}

	bar := pb.StartNew(len(addrs))
	for _, task := range addrs {
		bar.Increment()
		wg.Add(1)
		taskChan <- task
	}
	close(taskChan)
	wg.Wait()
	bar.Finish()

	return
}

// conn 建立tcp连接
func (r *Runner) conn(ipAddr *IpAddr) (alive bool) {
	_, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", ipAddr.Ip, ipAddr.Port), time.Duration(r.options.Timeout)*time.Second)
	if err == nil {
		alive = true
	}
	return
}
