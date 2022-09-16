package dirscan

type Result struct {
	Url           string
	StatusCode    int
	ContentLength int
}

// Results 按照contentLength排序
type Results []*Result

func (s Results) Len() int {
	return len(s)
}
func (s Results) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s Results) Less(i, j int) bool {
	return s[i].ContentLength < s[j].ContentLength
}
