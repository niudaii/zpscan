package domainscan

import (
	"testing"
)

func TestLayer(t *testing.T) {
	subdomainData := []string{"a1", "b1", "c1", "d1"}
	subnextData := []string{"a2", "b2", "c2", "d2"}
	op1 := &Options{
		Layer:          1,
		ProviderConfig: "",
		SubdomainData:  subdomainData,
		SubnextData:    subnextData,
	}
	e1, err := NewRunner(op1)
	if err != nil {
		t.Errorf("NewEngine err, %v", err)
	}
	op2 := &Options{
		Layer:          2,
		ProviderConfig: "",
		SubdomainData:  subdomainData,
		SubnextData:    subnextData,
	}
	e2, _ := NewRunner(op2)
	tests := map[string]*Runner{
		"layer1": e1,
		"layer2": e2,
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tc.Run([]string{"dbappsecurity.com.cn"})
		})
	}
}

func TestCheckCDN(t *testing.T) {
	subdomainData := []string{""}
	subnextData := []string{""}
	options := &Options{
		Layer:          1,
		ProviderConfig: "",
		SubdomainData:  subdomainData,
		SubnextData:    subnextData,
	}
	engine, err := NewRunner(options)
	if err != nil {
		t.Errorf("NewEngine err, %v", err)
	}
	if engine.CheckCDN("42.236.6.1") {
		t.Log("pass")
	}
}
