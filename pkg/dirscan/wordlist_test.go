package dirscan

import (
	"fmt"
	"testing"
)

func TestGenerateIpDir(t *testing.T) {
	results := GenerateIpDirs("106.75.26.139")
	fmt.Println(results)
}

func TestGenerateDomainiDir(t *testing.T) {
	results := GenerateDomainDirs("cpms.nbcb.com.cn")
	fmt.Println(results)
}
