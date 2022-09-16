package portscan

import (
	"flag"
	"fmt"
	"net"

	"github.com/niudaii/ipscan/pkg/ipscan/portscan/privileges"
	"github.com/pkg/errors"
)

var (
	errNoInputList = errors.New("no input list provided")
	//errOutputMode    = errors.New("both verbose and silent mode specified")
	errZeroValue = errors.New("cannot be zero")
	//errTwoOutputMode = errors.New("both json and csv mode specified")
)

// ValidateOptions  validates the configuration options passed
func (o *Options) ValidateOptions() error {
	// Check if Host, list of domains, or stdin info was provided.
	// If none was provided, then return.
	if len(o.Host) == 0 && !o.Stdin && len(flag.Args()) == 0 {
		return errNoInputList
	}

	if o.Timeout == 0 {
		return errors.Wrap(errZeroValue, "timeout")
	} else if !privileges.IsPrivileged && o.Timeout == DefaultPortTimeoutSynScan {
		o.Timeout = DefaultPortTimeoutConnectScan
	}

	if o.Rate == 0 {
		return errors.Wrap(errZeroValue, "rate")
	} else if !privileges.IsPrivileged && o.Rate == DefaultRateSynScan {
		o.Rate = DefaultRateConnectScan
	}

	if !privileges.IsPrivileged && o.Retries == DefaultRetriesSynScan {
		o.Retries = DefaultRetriesConnectScan
	}

	if o.Interface != "" {
		if _, err := net.InterfaceByName(o.Interface); err != nil {
			return fmt.Errorf("interface %s not found", o.Interface)
		}
	}

	return nil
}
