package portscan

const (
	DefaultPortTimeoutSynScan     = 1500
	DefaultPortTimeoutConnectScan = 5000

	DefaultRateSynScan     = 2000
	DefaultRateConnectScan = 1500

	DefaultRetriesSynScan     = 3
	DefaultRetriesConnectScan = 3

	ExternalTargetForTune = "8.8.8.8"

	SynScan              = "s"
	ConnectScan          = "c"
	DefaultStatsInterval = 5
)
