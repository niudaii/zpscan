package ksubdomain

import (
	"context"
	"github.com/boy-hack/ksubdomain/core/options"
	"github.com/boy-hack/ksubdomain/runner"
	"github.com/boy-hack/ksubdomain/runner/outputter"
)

type Result struct {
	Host string
	IP   string
}

func Run(domains []string, rate string) (results []*Result, err error) {
	buffPrinter, _ := NewBuffOutput()
	domainChanel := make(chan string)
	go func() {
		for _, d := range domains {
			domainChanel <- d
		}
		close(domainChanel)
	}()
	opt := &options.Options{
		Rate:        options.Band2Rate(rate),
		Domain:      domainChanel,
		DomainTotal: len(domains),
		Resolvers:   options.GetResolvers(""),
		Silent:      false,
		TimeOut:     10,
		Retry:       3,
		Method:      runner.VerifyType,
		DnsType:     "a",
		Writer: []outputter.Output{
			buffPrinter,
		},
		EtherInfo: options.GetDeviceConfig(),
	}
	opt.Check()
	r, err := runner.New(opt)
	if err != nil {
		return
	}
	r.RunEnumeration(context.Background())
	r.Close()
	return buffPrinter.Output(), nil
}
