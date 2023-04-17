package ksubdomain

import (
	"fmt"
	"github.com/boy-hack/ksubdomain/runner/result"
)

type BuffOutput struct {
	sb []*Result
}

func NewBuffOutput() (*BuffOutput, error) {
	s := &BuffOutput{}
	return s, nil
}

func (b *BuffOutput) WriteDomainResult(domain result.Result) error {
	fmt.Printf("%v => %v\n", domain.Subdomain, domain.Answers)
	b.sb = append(b.sb, &Result{
		Host: domain.Subdomain,
		IP:   domain.Answers[0],
	})
	return nil
}
func (b *BuffOutput) Close() {
	b.sb = nil
}
func (b *BuffOutput) Output() []*Result {
	return b.sb
}
