package domainweb

import "testing"

func TestRun(t *testing.T) {
	results := Run([]string{"cdn.nbcb.com.cn"}, 500, 50, "")
	t.Logf("结果数量: %v", len(results))
	t.Log(results)
}
