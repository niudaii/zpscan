package scan

import "sync"

type Result struct {
	sync.RWMutex
	IPPorts map[string]map[int]struct{}
	IPS     map[string]struct{}
}

// NewResult structure
func NewResult() *Result {
	ipPorts := make(map[string]map[int]struct{})
	ips := make(map[string]struct{})
	return &Result{IPPorts: ipPorts, IPS: ips}
}

// AddPort to a specific ip
func (r *Result) AddPort(k string, v int) {
	r.Lock()
	defer r.Unlock()

	if _, ok := r.IPPorts[k]; !ok {
		r.IPPorts[k] = make(map[int]struct{})
	}

	r.IPPorts[k][v] = struct{}{}
	r.IPS[k] = struct{}{}
}

// SetPorts for a specific ip
func (r *Result) SetPorts(k string, v map[int]struct{}) {
	r.Lock()
	defer r.Unlock()

	r.IPPorts[k] = v
	r.IPS[k] = struct{}{}
}
