package subfinder

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

type result struct {
	m []string
}

func (r *result) Write(p []byte) (n int, err error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(p))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		r.m = append(r.m, scanner.Text())
	}
	n = len(p)
	err = nil
	return
}
func (r *result) Output() []string {
	return r.m
}

func Run(domains []string, providers *runner.Providers) ([]string, error) {
	runnerInstance, err := runner.NewRunner(&runner.Options{
		Threads:            10,                              // Thread controls the number of threads to use for active enumerations
		Timeout:            30,                              // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10,                              // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		Resolvers:          resolve.DefaultResolvers,        // Use the default list of resolvers by marshaling it to the config
		Sources:            passive.DefaultSources,          // Use the default list of passive sources
		AllSources:         passive.DefaultAllSources,       // Use the default list of all passive sources
		Recursive:          passive.DefaultRecursiveSources, // Use the default list of recursive sources
		Providers:          providers,                       // Use empty api keys for all providers
	})
	if err != nil {
		return nil, err
	}
	buf := result{}
	err = runnerInstance.EnumerateMultipleDomains(context.Background(), strings.NewReader(strings.Join(domains, "\n")), []io.Writer{&buf})
	if err != nil {
		return nil, err
	}
	return buf.Output(), nil
}
