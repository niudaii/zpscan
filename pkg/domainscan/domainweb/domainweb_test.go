package domainweb

import "testing"

func TestRun(t *testing.T) {
	results, err := Run("dbappsecurity.com.cn", "xxx", "xxx")
	if err != nil {
		t.Errorf("Run() err, %v", err)
	}
	t.Logf("结果数量: %v", len(results))
	t.Log(results)
}
