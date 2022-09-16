//go:build darwin

package privileges

import (
	"os"
)

// 判断运行是用户的权限，如果为0，则为root用户
// isPrivileged checks if the current process has the CAP_NET_RAW capability or is root
func isPrivileged() bool {
	return os.Geteuid() == 0
}
