package crack

var (
	PortNames = map[int]string{
		21:    "ftp",
		22:    "ssh",
		135:   "wmi",
		445:   "smb",
		1433:  "mssql",
		1521:  "oracle",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgres",
		6379:  "redis",
		11211: "memcached",
		27017: "mongodb",
	}

	SupportProtocols = map[string]bool{
		"ftp":       true,
		"ssh":       true,
		"wmi":       true,
		"wmihash":   true,
		"smb":       true,
		"mssql":     true,
		"oracle":    true,
		"mysql":     true,
		"rdp":       true,
		"postgres":  true,
		"redis":     true,
		"memcached": true,
		"mongodb":   true,
	}
)

var (
	userMap = map[string][]string{
		//"ftp": {"ftp", "admin", "www"},
		"ftp": {"ftp"},
		//"ssh":      {"root", "oracle", "admin"},
		"ssh":       {"root"},
		"wmi":       {"administrator"},
		"wmihash":   {"administrator"},
		"smb":       {"administrator"},
		"mssql":     {"sa"},
		"oracle":    {"oracle", "system"},
		"mysql":     {"root"},
		"rdp":       {"administrator"},
		"postgres":  {"postgres", "admin"},
		"redis":     {""},
		"memcached": {""},
		"mongodb":   {"admin", "root"},
	}

	templatePass = []string{"{user}", "{user}!@#123", "{user}!@#456", "{user}#123", "{user}*PWD", "{user}1", "{user}11", "{user}12#$", "{user}123", "{user}123456", "{user}@111", "{user}@123", "{user}@123#4", "{user}@2016", "{user}@2017", "{user}@2018", "{user}@2019", "{user}@2020", "{user}@2021", "{user}@2022", "{user}_123"}

	commonPass = []string{"", "!QAZ2wsx", "000000", "1", "111111", "123", "123123", "12313", "123321", "1234", "12345!@#$%abc", "123456", "12345678", "123456789", "1234567890", "12345678;abc", "123456Aa", "123qwe!@#", "123qweASD", "1q2w3e", "1qaz2wsx", "1QAZ2wsx", "1qaz@WSX", "1QAZ@WSX", "1qazxsw2", "654321", "666666", "8888888", "a11111", "a123123", "a12345", "a123456", "a123456", "a123456.", "Aa123123", "Aa1234", "Aa1234.", "Aa12345", "Aa12345.", "Aa123456", "Aa123456!", "Aa123456789", "abc+123", "abc123", "abc123456", "abc@123", "admin", "admin123", "Admin123", "admin123!@#", "admin888", "admin@123", "Admin@123", "Admin@1234", "admin@888", "adminadmin", "adminPwd", "Asdfg@123", "Charge123", "P@ssw0rd", "P@ssw0rd!", "P@ssword", "p@ssword", "pass123", "pass@123", "Passw0rd", "password", "qwe123", "qwe123!@#", "root", "sysadmin", "system", "test", "test123", "xcv@123", "zxc1qaz", "Zxcvb123"}
)
