package ksubdomain

import "testing"

func TestRun(t *testing.T) {
	results, err := Run([]string{"lpsm.leapmotor.com"}, "500000k")
	if err != nil {
		t.Errorf("%v", err)
	}
	for _, res := range results {
		t.Logf("%v => %v\n", res.IP, res.Host)
	}
}
