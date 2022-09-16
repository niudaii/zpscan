package webscan

type FingerRules []*FingerRule

func (f FingerRules) Len() int {
	return len(f)
}
func (f FingerRules) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}
func (f FingerRules) Less(i, j int) bool {
	return f[i].Name < f[j].Name
}

type FingerRule struct {
	Name    string    `json:"name"`
	Tags    []string  `json:"tags"`
	PocTags []string  `json:"pocTags"`
	Desc    string    `json:"desc"`
	Fingers []*Finger `json:"fingers"`
	HasPoc  bool      `json:"hasPoc"`
}

type Finger struct {
	Type  string  `json:"type"`
	Rules []*Rule `json:"rules"`
}

type Rule struct {
	Method   string `json:"method"`
	Location string `json:"location"`
	Keyword  string `json:"keyword"`
}
