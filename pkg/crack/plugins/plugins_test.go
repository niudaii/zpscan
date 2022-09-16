package plugins

import (
	"testing"
)

var RespMap = map[int]string{
	CrackSuccess: "success",
	CrackFail:    "fail",
	CrackError:   "error",
}

func TestFtpCrack(t *testing.T) {
	/*
		=== RUN   TestFtpCrack
		=== RUN   TestFtpCrack/success
		    plugins_test.go:43: success ftp:ftp
		=== RUN   TestFtpCrack/fail
		    plugins_test.go:43: fail ftp:xxx
		=== RUN   TestFtpCrack/error
		    plugins_test.go:43: error ftp:xxx
		--- PASS: TestFtpCrack (10.02s)
		    --- PASS: TestFtpCrack/success (0.01s)
		    --- PASS: TestFtpCrack/fail (0.01s)
		    --- PASS: TestFtpCrack/error (10.00s)
		PASS
		ok  	crack/pkg/crack/plugins	10.033s
	*/
	tests := map[string]Service{
		"success": {
			Ip:      "192.168.31.245",
			Port:    21,
			User:    "ftp",
			Pass:    "ftp",
			Timeout: 10,
		},
		"fail": {
			Ip:      "192.168.31.245",
			Port:    21,
			User:    "ftp",
			Pass:    "xxx",
			Timeout: 10,
		},
		"error": {
			Ip:      "127.0.0.2",
			Port:    21,
			User:    "ftp",
			Pass:    "xxx",
			Timeout: 10,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := FtpCrack(&tc)
			t.Logf("%v %v:%v", RespMap[got], tc.User, tc.Pass)
			if name != RespMap[got] {
				t.Error("sth wrong")
			}
		})
	}
}

func TestSshCrack(t *testing.T) {
	/*
		=== RUN   TestSshCrack
		=== RUN   TestSshCrack/success
			plugins_test.go:78: success root:root
		=== RUN   TestSshCrack/fail
			plugins_test.go:78: fail root:xxx
		=== RUN   TestSshCrack/error
			plugins_test.go:78: error root:xxx
		--- PASS: TestSshCrack (11.54s)
			--- PASS: TestSshCrack/success (0.14s)
			--- PASS: TestSshCrack/fail (1.40s)
			--- PASS: TestSshCrack/error (10.00s)
		PASS
		ok  	crack/pkg/crack/plugins	11.555s
	*/
	tests := map[string]Service{
		"success": {
			Ip:      "192.168.243.11",
			Port:    22,
			User:    "root",
			Pass:    "root",
			Timeout: 10,
		},
		"fail": {
			Ip:      "192.168.243.11",
			Port:    22,
			User:    "root",
			Pass:    "xxx",
			Timeout: 10,
		},
		"error": {
			Ip:      "127.0.0.2",
			Port:    22,
			User:    "root",
			Pass:    "xxx",
			Timeout: 10,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := SshCrack(&tc)
			t.Logf("%v %v:%v", RespMap[got], tc.User, tc.Pass)
			if name != RespMap[got] {
				t.Error("sth wrong")
			}
		})
	}
}

func TestWmiCrack(t *testing.T) {
	/*
		=== RUN   TestWmiCrack
		=== RUN   TestWmiCrack/success
			plugins_test.go:130: success administrator:123qweASD
		=== RUN   TestWmiCrack/fail
			plugins_test.go:130: fail administrator:xxx
		=== RUN   TestWmiCrack/error
			plugins_test.go:130: error administrator:xxx
		--- PASS: TestWmiCrack (10.95s)
			--- PASS: TestWmiCrack/success (0.09s)
			--- PASS: TestWmiCrack/fail (0.74s)
			--- PASS: TestWmiCrack/error (10.12s)
		PASS
		ok  	crack/pkg/crack/plugins	10.963s
	*/
	tests := map[string]Service{
		"success": {
			Ip:      "192.168.243.10",
			Port:    135,
			User:    "administrator",
			Pass:    "123qweASD",
			Timeout: 10,
		},
		"fail": {
			Ip:      "192.168.243.10",
			Port:    135,
			User:    "administrator",
			Pass:    "xxx",
			Timeout: 10,
		},
		"error": {
			Ip:      "127.0.0.2",
			Port:    135,
			User:    "administrator",
			Pass:    "xxx",
			Timeout: 10,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := WmiCrack(&tc)
			t.Logf("%v %v:%v", RespMap[got], tc.User, tc.Pass)
			if name != RespMap[got] {
				t.Error("sth wrong")
			}
		})
	}
}

func TestWmiHashCrack(t *testing.T) {
	/*
		=== RUN   TestWmiHashCrack
		=== RUN   TestWmiHashCrack/success
		    plugins_test.go:145: success administrator:257c7efa85ba45bb30b7da33f46a5225
		=== RUN   TestWmiHashCrack/fail
		    plugins_test.go:145: fail administrator:257c7efa85ba45bb30b7da33f46a5220
		=== RUN   TestWmiHashCrack/error
		    plugins_test.go:145: error administrator:257c7efa85ba45bb30b7da33f46a5220
		--- PASS: TestWmiHashCrack (10.02s)
		    --- PASS: TestWmiHashCrack/success (0.01s)
		    --- PASS: TestWmiHashCrack/fail (0.01s)
		    --- PASS: TestWmiHashCrack/error (10.00s)
		PASS
		ok  	crack/pkg/crack/plugins	10.031s
	*/
	tests := map[string]Service{
		"success": {
			Ip:      "192.168.243.10",
			Port:    135,
			User:    "administrator",
			Pass:    "257c7efa85ba45bb30b7da33f46a5225",
			Timeout: 10,
		},
		"fail": {
			Ip:      "192.168.243.10",
			Port:    135,
			User:    "administrator",
			Pass:    "257c7efa85ba45bb30b7da33f46a5220",
			Timeout: 10,
		},
		"error": {
			Ip:      "127.0.0.2",
			Port:    135,
			User:    "administrator",
			Pass:    "257c7efa85ba45bb30b7da33f46a5220",
			Timeout: 10,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := WmiHashCrack(&tc)
			t.Logf("%v %v:%v", RespMap[got], tc.User, tc.Pass)
			if name != RespMap[got] {
				t.Error("sth wrong")
			}
		})
	}
}

func TestSmbCrack(t *testing.T) {
	/*
		=== RUN   TestSmbCrack
		=== RUN   TestSmbCrack/success
		    plugins_test.go:181: success administrator:123qweASD
		=== RUN   TestSmbCrack/fail
		    plugins_test.go:181: fail administrator:xxx
		=== RUN   TestSmbCrack/error
		    plugins_test.go:181: error administrator:xxx
		--- PASS: TestSmbCrack (10.01s)
		    --- PASS: TestSmbCrack/success (0.01s)
		    --- PASS: TestSmbCrack/fail (0.01s)
		    --- PASS: TestSmbCrack/error (10.00s)
		PASS
		ok  	crack/pkg/crack/plugins	10.028s
	*/
	tests := map[string]Service{
		"success": {
			Ip:      "192.168.243.10",
			Port:    445,
			User:    "administrator",
			Pass:    "123qweASD",
			Timeout: 10,
		},
		"fail": {
			Ip:      "192.168.243.10",
			Port:    445,
			User:    "administrator",
			Pass:    "xxx",
			Timeout: 10,
		},
		"error": {
			Ip:      "127.0.0.2",
			Port:    445,
			User:    "administrator",
			Pass:    "xxx",
			Timeout: 10,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := SmbCrack(&tc)
			t.Logf("%v %v:%v", RespMap[got], tc.User, tc.Pass)
			if name != RespMap[got] {
				t.Error("sth wrong")
			}
		})
	}
}

func TestMssqlCrack(t *testing.T) {
	/*
		=== RUN   TestMssqlCrack
		=== RUN   TestMssqlCrack/success
		    plugins_test.go:218: success sa:123qweASD
		=== RUN   TestMssqlCrack/fail
		    plugins_test.go:218: fail sa:xxx
		=== RUN   TestMssqlCrack/error
		    plugins_test.go:218: error sa:xxx
		--- PASS: TestMssqlCrack (10.02s)
		    --- PASS: TestMssqlCrack/success (0.01s)
		    --- PASS: TestMssqlCrack/fail (0.01s)
		    --- PASS: TestMssqlCrack/error (10.00s)
		PASS
		ok  	crack/pkg/crack/plugins	10.031s
	*/
	tests := map[string]Service{
		"success": {
			Ip:      "127.0.0.1",
			Port:    1433,
			User:    "sa",
			Pass:    "123qweASD",
			Timeout: 10,
		},
		"fail": {
			Ip:      "127.0.0.1",
			Port:    1433,
			User:    "sa",
			Pass:    "xxx",
			Timeout: 10,
		},
		"error": {
			Ip:      "127.0.0.2",
			Port:    1433,
			User:    "sa",
			Pass:    "xxx",
			Timeout: 10,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := MssqlCrack(&tc)
			t.Logf("%v %v:%v", RespMap[got], tc.User, tc.Pass)
			if name != RespMap[got] {
				t.Error("sth wrong")
			}
		})
	}
}

func TestOracleCrack(t *testing.T) {
	/*
		=== RUN   TestOracleCrack
		=== RUN   TestOracleCrack/success
		&{28002 4 ORA-28002: the password will expire within 5 days
		}
		    plugins_test.go:253: success system:oracle
		=== RUN   TestOracleCrack/fail
		    plugins_test.go:253: fail system:xxx
		=== RUN   TestOracleCrack/error
		    plugins_test.go:253: error system:xxx
		--- PASS: TestOracleCrack (10.08s)
		    --- PASS: TestOracleCrack/success (0.05s)
		    --- PASS: TestOracleCrack/fail (0.03s)
		    --- PASS: TestOracleCrack/error (10.00s)
		PASS
		ok  	crack/pkg/crack/plugins	10.096s
	*/
	tests := map[string]Service{
		"success": {
			Ip:      "127.0.0.1",
			Port:    1521,
			User:    "system",
			Pass:    "oracle",
			Timeout: 10,
		},
		"fail": {
			Ip:      "127.0.0.1",
			Port:    1521,
			User:    "system",
			Pass:    "xxx",
			Timeout: 10,
		},
		"error": {
			Ip:      "127.0.0.2",
			Port:    1521,
			User:    "system",
			Pass:    "xxx",
			Timeout: 10,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := OracleCrack(&tc)
			t.Logf("%v %v:%v", RespMap[got], tc.User, tc.Pass)
			if name != RespMap[got] {
				t.Error("sth wrong")
			}
		})
	}
}

func TestMysqlCrack(t *testing.T) {
	/*
		=== RUN   TestMysqlCrack
		=== RUN   TestMysqlCrack/success
		    plugins_test.go:288: success root:123456
		=== RUN   TestMysqlCrack/fail
		    plugins_test.go:288: fail root:xxx
		=== RUN   TestMysqlCrack/error
		    plugins_test.go:288: error root:xxx
		--- PASS: TestMysqlCrack (10.02s)
		    --- PASS: TestMysqlCrack/success (0.01s)
		    --- PASS: TestMysqlCrack/fail (0.00s)
		    --- PASS: TestMysqlCrack/error (10.00s)
		PASS
		ok  	crack/pkg/crack/plugins	10.029s
	*/
	tests := map[string]Service{
		"success": {
			Ip:   "127.0.0.1",
			Port: 3306,
			//User:    "root",
			//Pass:    "123456",
			User:    "test_user",
			Pass:    "test2022@",
			Timeout: 10,
		},
		"fail": {
			Ip:      "127.0.0.1",
			Port:    3306,
			User:    "root",
			Pass:    "xxx",
			Timeout: 10,
		},
		"error": {
			Ip:      "127.0.0.2",
			Port:    3306,
			User:    "root",
			Pass:    "xxx",
			Timeout: 10,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := MysqlCrack(&tc)
			t.Logf("%v %v:%v", RespMap[got], tc.User, tc.Pass)
			if name != RespMap[got] {
				t.Error("sth wrong")
			}
		})
	}
}

func TestRdpCrack(t *testing.T) {
	/*
		=== RUN   TestRdpCrack
		=== RUN   TestRdpCrack/success
		    plugins_test.go:321: success administrator:123qweASD
		=== RUN   TestRdpCrack/fail
		    plugins_test.go:321: fail administrator:xxx
		=== RUN   TestRdpCrack/error
		    plugins_test.go:321: error administrator:xxx
		--- PASS: TestRdpCrack (11.21s)
		    --- PASS: TestRdpCrack/success (0.12s)
		    --- PASS: TestRdpCrack/fail (1.09s)
		    --- PASS: TestRdpCrack/error (10.00s)
		PASS
		ok  	crack/pkg/crack/plugins	11.225s
	*/
	tests := map[string]Service{
		"success": {
			Ip:      "192.168.243.10",
			Port:    3389,
			User:    "administrator",
			Pass:    "123qweASD",
			Timeout: 10,
		},
		"fail": {
			Ip:      "192.168.243.10",
			Port:    3389,
			User:    "administrator",
			Pass:    "xxx",
			Timeout: 10,
		},
		"error": {
			Ip:      "192.168.243.11",
			Port:    3389,
			User:    "administrator",
			Pass:    "xxx",
			Timeout: 10,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := RdpCrack(&tc)
			t.Logf("%v %v:%v", RespMap[got], tc.User, tc.Pass)
			if name != RespMap[got] {
				t.Error("sth wrong")
			}
		})
	}
}

func TestPostgresCrack(t *testing.T) {
	/*
		=== RUN   TestPostgresCrack
		=== RUN   TestPostgresCrack/success
		    plugins_test.go:355: success postgres:password
		=== RUN   TestPostgresCrack/fail
		    plugins_test.go:355: fail postgres:xxx
		=== RUN   TestPostgresCrack/error
		    plugins_test.go:355: error postgres:xxx
		--- PASS: TestPostgresCrack (10.01s)
		    --- PASS: TestPostgresCrack/success (0.01s)
		    --- PASS: TestPostgresCrack/fail (0.01s)
		    --- PASS: TestPostgresCrack/error (10.00s)
		PASS
		ok  	crack/pkg/crack/plugins	10.027s
	*/
	tests := map[string]Service{
		"success": {
			Ip:      "127.0.0.1",
			Port:    5432,
			User:    "postgres",
			Pass:    "password",
			Timeout: 10,
		},
		"fail": {
			Ip:      "127.0.0.1",
			Port:    5432,
			User:    "postgres",
			Pass:    "xxx",
			Timeout: 10,
		},
		"error": {
			Ip:      "127.0.0.2",
			Port:    5432,
			User:    "postgres",
			Pass:    "xxx",
			Timeout: 10,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := PostgresCrack(&tc)
			t.Logf("%v %v:%v", RespMap[got], tc.User, tc.Pass)
			if name != RespMap[got] {
				t.Error("sth wrong")
			}
		})
	}
}

func TestRedisCrack(t *testing.T) {
	/*
		=== RUN   TestRedisCrack
		=== RUN   TestRedisCrack/success
		    plugins_test.go:390: success :123456
		=== RUN   TestRedisCrack/fail
		    plugins_test.go:390: fail :xxx
		=== RUN   TestRedisCrack/error
		    plugins_test.go:390: error :xxx
		--- PASS: TestRedisCrack (10.02s)
		    --- PASS: TestRedisCrack/success (0.02s)
		    --- PASS: TestRedisCrack/fail (0.00s)
		    --- PASS: TestRedisCrack/error (10.00s)
		PASS
		ok  	crack/pkg/crack/plugins	10.036s
	*/
	tests := map[string]Service{
		"success": {
			Ip:      "127.0.0.1",
			Port:    6379,
			User:    "",
			Pass:    "123456",
			Timeout: 10,
		},
		"fail": {
			Ip:      "127.0.0.1",
			Port:    6379,
			User:    "",
			Pass:    "xxx",
			Timeout: 10,
		},
		"error": {
			Ip:      "127.0.0.2",
			Port:    6379,
			User:    "",
			Pass:    "xxx",
			Timeout: 10,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := RedisCrack(&tc)
			t.Logf("%v %v:%v", RespMap[got], tc.User, tc.Pass)
			if name != RespMap[got] {
				t.Error("sth wrong")
			}
		})
	}
}

func TestMemcachedCrack(t *testing.T) {
	/*
		只检查未授权，不需要 TestMongodbCrack/fail 测试用例

		=== RUN   TestMemcachedCrack
		=== RUN   TestMemcachedCrack/error
		    plugins_test.go:432: error :xxx
		=== RUN   TestMemcachedCrack/success
		    plugins_test.go:432: success :xxx
		--- PASS: TestMemcachedCrack (10.01s)
		    --- PASS: TestMemcachedCrack/error (10.00s)
		    --- PASS: TestMemcachedCrack/success (0.01s)
		PASS
		ok  	crack/pkg/crack/plugins	10.021s
	*/
	tests := map[string]Service{
		"success": {
			Ip:      "127.0.0.1",
			Port:    11211,
			User:    "",
			Pass:    "xxx",
			Timeout: 10,
		},
		"error": {
			Ip:      "127.0.0.2",
			Port:    11211,
			User:    "",
			Pass:    "xxx",
			Timeout: 10,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := MemcachedCrack(&tc)
			t.Logf("%v %v:%v", RespMap[got], tc.User, tc.Pass)
			if name != RespMap[got] {
				t.Error("sth wrong")
			}
		})
	}
}

func TestMongodbCrack(t *testing.T) {
	/*
		=== RUN   TestMongodbCrack
		=== RUN   TestMongodbCrack/success
		    plugins_test.go:413: success admin:123456
		=== RUN   TestMongodbCrack/fail
		    plugins_test.go:413: fail admin:xxx
		=== RUN   TestMongodbCrack/error
		    plugins_test.go:413: error admin:xxx
		--- PASS: TestMongodbCrack (10.01s)
		    --- PASS: TestMongodbCrack/success (0.01s)
		    --- PASS: TestMongodbCrack/fail (0.00s)
		    --- PASS: TestMongodbCrack/error (10.00s)
		PASS
		ok  	crack/pkg/crack/plugins	10.026s

		未授权时 TestMongodbCrack/fail 认证通过

		=== RUN   TestMongodbCrack
		=== RUN   TestMongodbCrack/error
		    plugins_test.go:428: error admin:xxx
		=== RUN   TestMongodbCrack/success
		    plugins_test.go:428: success admin:123456
		=== RUN   TestMongodbCrack/fail
		    plugins_test.go:428: success admin:xxx
		    plugins_test.go:430: sth wrong
		--- FAIL: TestMongodbCrack (10.00s)
		    --- PASS: TestMongodbCrack/error (10.00s)
		    --- PASS: TestMongodbCrack/success (0.00s)
		    --- FAIL: TestMongodbCrack/fail (0.00s)
		FAIL
		exit status 1
		FAIL	crack/pkg/crack/plugins	10.016s
	*/
	tests := map[string]Service{
		"success": {
			Ip:      "127.0.0.1",
			Port:    27017,
			User:    "admin",
			Pass:    "123456",
			Timeout: 10,
		},
		"fail": {
			Ip:      "127.0.0.1",
			Port:    27017,
			User:    "admin",
			Pass:    "xxx",
			Timeout: 10,
		},
		"error": {
			Ip:      "127.0.0.2",
			Port:    27017,
			User:    "admin",
			Pass:    "xxx",
			Timeout: 10,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := MongodbCrack(&tc)
			t.Logf("%v %v:%v", RespMap[got], tc.User, tc.Pass)
			if name != RespMap[got] {
				t.Error("sth wrong")
			}
		})
	}
}
