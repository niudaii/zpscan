package plugins

type Service struct {
	Ip       string
	Port     int
	Protocol string
	User     string
	Pass     string
	Timeout  int
}

const (
	CrackError = iota
	CrackFail
	CrackSuccess
)

type ScanFunc func(serv *Service) int

var (
	ScanFuncMap map[string]ScanFunc
)

func init() {
	ScanFuncMap = make(map[string]ScanFunc)
	ScanFuncMap["ftp"] = FtpCrack
	ScanFuncMap["ssh"] = SshCrack
	ScanFuncMap["wmi"] = WmiCrack
	ScanFuncMap["wmihash"] = WmiHashCrack
	ScanFuncMap["smb"] = SmbCrack
	ScanFuncMap["mssql"] = MssqlCrack
	ScanFuncMap["oracle"] = OracleCrack
	ScanFuncMap["mysql"] = MysqlCrack
	ScanFuncMap["rdp"] = RdpCrack
	ScanFuncMap["postgres"] = PostgresCrack
	ScanFuncMap["redis"] = RedisCrack
	ScanFuncMap["memcached"] = MemcachedCrack
	ScanFuncMap["mongodb"] = MongodbCrack
}
