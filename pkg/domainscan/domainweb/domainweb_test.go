package domainweb

import "testing"

func TestRun(t *testing.T) {
	results, err := Run("dbappsecurity.com.cn", "243536998@qq.com", "357e4effe1d5bae1b56715fa343a6423")
	if err != nil {
		t.Errorf("Run() err, %v", err)
	}
	t.Logf("结果数量: %v", len(results))
	t.Log(results)
}
