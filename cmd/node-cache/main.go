package main

import (
	"fmt"
	"github.com/mholt/caddy"

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
	setupIptables        bool
}

type iptablesRule struct {
	table utiliptables.Table
	chain utiliptables.Chain
	args  []string
}

type cacheApp struct {
	params        configParams
	netifHandle   *netif.NetifManager
}

func isLockedErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "holding the xtables lock")
}

func iptablesRules(localIPStr, localPort string) []iptablesRule {
	r := make([]iptablesRule, 0)
	// using the localIPStr param since we need ip strings here
	for _, localIP := range strings.Split(localIPStr, ",") {
		r = append(r, []iptablesRule{
			// Match traffic destined for localIp:localPort and set the flows to be NOTRACKED, this skips connection tracking
			{utiliptables.Table("raw"), utiliptables.ChainPrerouting, []string{"-p", "tcp", "-d", localIP,
				"--dport", localPort, "-j", "NOTRACK"}},
			{utiliptables.Table("raw"), utiliptables.ChainPrerouting, []string{"-p", "udp", "-d", localIP,
				"--dport", localPort, "-j", "NOTRACK"}},
			// There are rules in filter table to allow tracked connections to be accepted. Since we skipped connection tracking,
			// need these additional filter table rules.
			{utiliptables.TableFilter, utiliptables.ChainInput, []string{"-p", "tcp", "-d", localIP,
				"--dport", localPort, "-j", "ACCEPT"}},
			{utiliptables.TableFilter, utiliptables.ChainInput, []string{"-p", "udp", "-d", localIP,
				"--dport", localPort, "-j", "ACCEPT"}},
			// Match traffic from localIp:localPort and set the flows to be NOTRACKED, this skips connection tracking
			{utiliptables.Table("raw"), utiliptables.ChainOutput, []string{"-p", "tcp", "-s", localIP,
				"--sport", localPort, "-j", "NOTRACK"}},
			{utiliptables.Table("raw"), utiliptables.ChainOutput, []string{"-p", "udp", "-s", localIP,
				"--sport", localPort, "-j", "NOTRACK"}},
			// Additional filter table rules for traffic frpm localIp:localPort
			{utiliptables.TableFilter, utiliptables.ChainOutput, []string{"-p", "tcp", "-s", localIP,
				"--sport", localPort, "-j", "ACCEPT"}},
			{utiliptables.TableFilter, utiliptables.ChainOutput, []string{"-p", "udp", "-s", localIP,
				"--sport", localPort, "-j", "ACCEPT"}},
		}...)
	}

	return r
}

func teardownNetworking(ifm *netif.NetifManager, params configParams) error {
	clog.Infof("Tearing down")
	if err := ifm.RemoveDummyDevice(params.interfaceName); err != nil {
		clog.Infof("Failed removing interface %s", params.interfaceName)
	}

	if params.setupIptables {
		iptables := utiliptables.New(utilexec.New(), dbus.New(), utiliptables.ProtocolIpv4)
		for _, rule := range iptablesRules(params.localIPStr, params.localPort) {
			clog.Infof("Deleting rule %+v\n", rule)

			err := iptables.DeleteRule(rule.table, rule.chain, rule.args...)
			for isLockedErr(err) {
				err = iptables.DeleteRule(rule.table, rule.chain, rule.args...)
				time.Sleep(100 * time.Millisecond)
			}
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func parseAndValidateFlags() (configParams, error) {
	var cp = configParams{}

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
			return cp, fmt.Errorf("Invalid localip specified - %q", ipstr)
		}
		cp.localIPs = append(cp.localIPs, newIP)
	}

	// lookup specified dns port
	if f := flag.Lookup("dns.port"); f == nil {
		cp.localPort = "53"
	} else {
		cp.localPort = f.Value.String()
	}
	if _, err := strconv.Atoi(cp.localPort); err != nil {
		return cp, fmt.Errorf("Invalid port specified - %q", cp.localPort)
	}
	return cp, nil
}

func ensureNetworkSetup(ifm *netif.NetifManager, params configParams) error {
	exists, err := ifm.EnsureDummyDevice(params.interfaceName)
	if err != nil {
		clog.Errorf("Error ensuring dummy interface %s is present - %s", params.interfaceName, err)
		setupErrCount.WithLabelValues("interface_check").Inc()
		return err
	}

	if !exists {
		clog.Infof("Added interface - %s", params.interfaceName)
	}

	if params.setupIptables {
		iptables := utiliptables.New(utilexec.New(), dbus.New(), utiliptables.ProtocolIpv4)

		for _, rule := range iptablesRules(params.localIPStr, params.localPort) {
			exists, err := iptables.EnsureRule(utiliptables.Prepend, rule.table, rule.chain, rule.args...)
			switch {
			case exists:
				// debug messages can be printed by including "debug" plugin in coreFile.
				clog.Debugf("iptables rule %v for nodelocaldns already exists", rule)
				continue
			case err == nil:
				clog.Infof("Added nodelocaldns rule - %v", rule)
				continue
			default:
				setupErrCount.WithLabelValues("iptables").Inc()
				return fmt.Errorf("Error adding iptables rule %v - %s", rule, err)
			}
		}
	}

	return nil
}

func run() {
	cp, err := parseAndValidateFlags()
	if err != nil {
		clog.Fatalf("Error parsing flags - %s, Exiting", err)
	}

	ifm := netif.NewNetifManager(cp.localIPs)
	caddy.OnProcessExit = append(caddy.OnProcessExit, func() {teardownNetworking(ifm, cp)})

	initMetrics(cp.metricsListenAddress)

	retryInterval := 100*time.Millisecond
	err = ensureNetworkSetup(ifm, cp)
	for isLockedErr(err) {
		clog.Errorf("Error setting up networking: %s - retrying...", err)
		time.Sleep(retryInterval)
		err = ensureNetworkSetup(ifm, cp)
	}

	if err != nil {
		clog.Fatalf("Error setting up networking - %s, Exiting", err)
	}

	coremain.Run()
}

func main() {
	run()
}
