package nuclei

import (
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
)

type fakeWrite struct{}

func (r *fakeWrite) Close() {}
func (r *fakeWrite) Colorizer() aurora.Aurora {
	return nil
}
func (r *fakeWrite) WriteFailure(event output.InternalEvent) error                       { return nil }
func (r *fakeWrite) Write(w *output.ResultEvent) error                                   { return nil }
func (r *fakeWrite) Request(templateID, url, requestType string, err error)              {}
func (r *fakeWrite) WriteStoreDebugData(host, templateID, eventType string, data string) {}

type fakeProgress struct{}

func (p *fakeProgress) Stop()                                                    {}
func (p *fakeProgress) Init(hostCount int64, rulesCount int, requestCount int64) {}
func (p *fakeProgress) AddToTotal(delta int64)                                   {}
func (p *fakeProgress) IncrementRequests()                                       {}
func (p *fakeProgress) IncrementMatched()                                        {}
func (p *fakeProgress) IncrementErrorsBy(count int64)                            {}
func (p *fakeProgress) IncrementFailedRequestsBy(count int64)                    {}
