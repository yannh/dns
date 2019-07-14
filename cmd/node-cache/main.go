package main

import (
	"fmt"

	"flag"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/coredns/coremain"
	_ "github.com/coredns/coredns/plugin/bind"
	_ "github.com/coredns/coredns/plugin/cache"
	_ "github.com/coredns/coredns/plugin/errors"
	_ "github.com/coredns/coredns/plugin/forward"
	_ "github.com/coredns/coredns/plugin/health"
	_ "github.com/coredns/coredns/plugin/log"
	_ "github.com/coredns/coredns/plugin/loop"
	_ "github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	_ "github.com/coredns/coredns/plugin/reload"
	"k8s.io/dns/pkg/netif"
	"k8s.io/kubernetes/pkg/util/dbus"
	utilexec "k8s.io/kubernetes/pkg/util/exec"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
)

// configParams lists the configuration options that can be provided to dns-cache
type configParams struct {
	localIPStr           string        // comma separated listen ips for the local cache agent
	localIPs             []net.IP      // parsed ip addresses for the local cache agent to listen for dns requests
	localPort            string        // port to listen for dns requests
	metricsListenAddress string        // address to serve metrics on
	interfaceName        string        // Name of the interface to be created
	interval             time.Duration // specifies how often to run iptables rules check
	setupIptables bool
}

type iptablesRule struct {
	table utiliptables.Table
	chain utiliptables.Chain
	args  []string
}

type cacheApp struct {
	iptables      utiliptables.Interface
	iptablesRules []iptablesRule
	params        configParams
	netifHandle   *netif.NetifManager
}

func (c *cacheApp) initIptables() {
	// using the localIPStr param since we need ip strings here
	for _, localIP := range strings.Split(c.params.localIPStr, ",") {
		c.iptablesRules = append(c.iptablesRules, []iptablesRule{
			// Match traffic destined for localIp:localPort and set the flows to be NOTRACKED, this skips connection tracking
			{utiliptables.Table("raw"), utiliptables.ChainPrerouting, []string{"-p", "tcp", "-d", localIP,
				"--dport", c.params.localPort, "-j", "NOTRACK"}},
			{utiliptables.Table("raw"), utiliptables.ChainPrerouting, []string{"-p", "udp", "-d", localIP,
				"--dport", c.params.localPort, "-j", "NOTRACK"}},
			// There are rules in filter table to allow tracked connections to be accepted. Since we skipped connection tracking,
			// need these additional filter table rules.
			{utiliptables.TableFilter, utiliptables.ChainInput, []string{"-p", "tcp", "-d", localIP,
				"--dport", c.params.localPort, "-j", "ACCEPT"}},
			{utiliptables.TableFilter, utiliptables.ChainInput, []string{"-p", "udp", "-d", localIP,
				"--dport", c.params.localPort, "-j", "ACCEPT"}},
			// Match traffic from localIp:localPort and set the flows to be NOTRACKED, this skips connection tracking
			{utiliptables.Table("raw"), utiliptables.ChainOutput, []string{"-p", "tcp", "-s", localIP,
				"--sport", c.params.localPort, "-j", "NOTRACK"}},
			{utiliptables.Table("raw"), utiliptables.ChainOutput, []string{"-p", "udp", "-s", localIP,
				"--sport", c.params.localPort, "-j", "NOTRACK"}},
			// Additional filter table rules for traffic frpm localIp:localPort
			{utiliptables.TableFilter, utiliptables.ChainOutput, []string{"-p", "tcp", "-s", localIP,
				"--sport", c.params.localPort, "-j", "ACCEPT"}},
			{utiliptables.TableFilter, utiliptables.ChainOutput, []string{"-p", "udp", "-s", localIP,
				"--sport", c.params.localPort, "-j", "ACCEPT"}},
		}...)
	}

	c.iptables = utiliptables.New(utilexec.New(), dbus.New(), utiliptables.ProtocolIpv4)
}

func (c *cacheApp) teardownNetworking() error {
	clog.Infof("Tearing down")
	if err := c.netifHandle.RemoveDummyDevice(c.params.interfaceName); err != nil {
		clog.Infof("Failed removing interface %s", c.params.interfaceName)
	}

	if c.params.setupIptables {
		for _, rule := range c.iptablesRules {
			if err := c.iptables.DeleteRule(rule.table, rule.chain, rule.args...); err != nil {
				return err
			}
		}
	}

	return nil
}

func parseAndValidateFlags() (*configParams, error) {
	var cp = &configParams{}

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Runs coreDNS v1.2.5 as a nodelocal cache listening on the specified ip:port")
		flag.PrintDefaults()
	}

	flag.StringVar(&cp.localIPStr, "localip", "", "comma-separated string of ip addresses to bind dnscache to")
	flag.StringVar(&cp.interfaceName, "interfacename", "nodelocaldns", "name of the interface to be created")
	flag.StringVar(&cp.metricsListenAddress, "metrics-listen-address", "0.0.0.0:9353", "address to serve metrics on")
	flag.BoolVar(&cp.setupIptables, "setupiptables", true, "indicates whether iptables rules should be setup")
	flag.Parse()

	for _, ipstr := range strings.Split(cp.localIPStr, ",") {
		newIP := net.ParseIP(ipstr)
		if newIP == nil {
			return nil, fmt.Errorf("Invalid localip specified - %q", ipstr)
		}
		cp.localIPs = append(cp.localIPs, newIP)
	}

	// lookup specified dns port
	if f := flag.Lookup("dns.port"); f == nil {
		return nil, fmt.Errorf("Failed to lookup \"dns.port\" parameter")
	} else {
		cp.localPort = f.Value.String()
	}
	if _, err := strconv.Atoi(cp.localPort); err != nil {
		return nil, fmt.Errorf("Invalid port specified - %q", cp.localPort)
	}
	return cp, nil
}

func (c *cacheApp) ensureNetworkSetup() error {
	exists, err := c.netifHandle.EnsureDummyDevice(c.params.interfaceName)
	if err != nil {
		clog.Errorf("Error ensuring dummy interface %s is present - %s", c.params.interfaceName, err)
		setupErrCount.WithLabelValues("interface_check").Inc()
		return err
	}

	if !exists {
		clog.Infof("Added interface - %s", c.params.interfaceName)
	}

	if c.params.setupIptables {
		isLockedErr := func (err error) bool {
			return strings.Contains(err.Error(), "holding the xtables lock")
		}

		for _, rule := range c.iptablesRules {
			exists, err := c.iptables.EnsureRule(utiliptables.Prepend, rule.table, rule.chain, rule.args...)
			switch {
			case exists:
				// debug messages can be printed by including "debug" plugin in coreFile.
				clog.Debugf("iptables rule %v for nodelocaldns already exists", rule)
				continue
			case err == nil:
				clog.Infof("Added back nodelocaldns rule - %v", rule)
				continue
			// if we got here, either iptables check failed or adding rule back failed.
			case isLockedErr(err):
				return fmt.Errorf("Error checking/adding iptables rule %v, due to xtables lock in use", rule)
				setupErrCount.WithLabelValues("iptables_lock").Inc()
				return err
			default:
				clog.Errorf("Error adding iptables rule %v - %s", rule, err)
				setupErrCount.WithLabelValues("iptables").Inc()
				return err
			}
		}
	}

	return nil
}

func real_main() {
	var cache = cacheApp{params: configParams{localPort: "53"}}
	defer cache.teardownNetworking()


	if cp, err := parseAndValidateFlags(); err != nil {
		clog.Fatalf("Error parsing flags - %s, Exiting", err)
	} else {
		cache.params = *cp
	}

	cache.netifHandle = netif.NewNetifManager(cache.params.localIPs)
	if cache.params.setupIptables {
		cache.initIptables()
	}

	initMetrics(cache.params.metricsListenAddress)

	retries := 0
	maxSetupRetries := 5
	err := cache.ensureNetworkSetup()
	for err != nil && retries < maxSetupRetries {
		clog.Errorf("Error setting up networking: %s - retrying...", err)
		retries++
		time.Sleep(time.Second)
		err = cache.ensureNetworkSetup()
	}

	if retries == maxSetupRetries {
		clog.Fatalf("Failed setting up networking after %d retries. Exiting", maxSetupRetries)
	}

	coremain.Run()
}

func main() {
  real_main()
}
