package domainweb

import "testing"

func TestRun(t *testing.T) {
	results := Run([]string{"weixincloud.nbcb.com.cn"}, 1, 50, "")
	t.Logf("结果数量: %v", len(results))
	t.Log(results)
}
