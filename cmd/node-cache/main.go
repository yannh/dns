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
type nodeCacheConfig struct {
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

type DummyDeviceEnsurer interface {
	EnsureDummyDevice(ifName string) (bool, error)
}

type DummyDeviceRemover interface {
	RemoveDummyDevice(ifName string) error
}

func parseAndValidateFlags() (nodeCacheConfig, error) {
	var cp = nodeCacheConfig{}

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

	cp.localPort = "53"
	if f := flag.Lookup("dns.port"); f != nil {
		cp.localPort = f.Value.String()
	}

	if _, err := strconv.Atoi(cp.localPort); err != nil {
		return cp, fmt.Errorf("Invalid port specified - %q", cp.localPort)
	}

	return cp, nil
}

func iptablesRules(localIPStr, localPort string) []iptablesRule {
	r := make([]iptablesRule, 0)
	// using the localIPStr param since we need ip strings here
	for _, localIP := range strings.Split(localIPStr, ",") {
		r = append(r, []iptablesRule{
			// Match traffic destined for localIp:localPort and set the flows to be NOTRACKED, this skips connection tracking
			{utiliptables.Table("raw"), utiliptables.ChainPrerouting, []string{"-p", "tcp", "-d", localIP,
				"--dport", localPort, "-j", "NOTRACK", "-w"}},
			{utiliptables.Table("raw"), utiliptables.ChainPrerouting, []string{"-p", "udp", "-d", localIP,
				"--dport", localPort, "-j", "NOTRACK", "-w"}},
			// There are rules in filter table to allow tracked connections to be accepted. Since we skipped connection tracking,
			// need these additional filter table rules.
			{utiliptables.TableFilter, utiliptables.ChainInput, []string{"-p", "tcp", "-d", localIP,
				"--dport", localPort, "-j", "ACCEPT", "-w"}},
			{utiliptables.TableFilter, utiliptables.ChainInput, []string{"-p", "udp", "-d", localIP,
				"--dport", localPort, "-j", "ACCEPT", "-w"}},
			// Match traffic from localIp:localPort and set the flows to be NOTRACKED, this skips connection tracking
			{utiliptables.Table("raw"), utiliptables.ChainOutput, []string{"-p", "tcp", "-s", localIP,
				"--sport", localPort, "-j", "NOTRACK", "-w"}},
			{utiliptables.Table("raw"), utiliptables.ChainOutput, []string{"-p", "udp", "-s", localIP,
				"--sport", localPort, "-j", "NOTRACK", "-w"}},
			// Additional filter table rules for traffic frpm localIp:localPort
			{utiliptables.TableFilter, utiliptables.ChainOutput, []string{"-p", "tcp", "-s", localIP,
				"--sport", localPort, "-j", "ACCEPT", "-w"}},
			{utiliptables.TableFilter, utiliptables.ChainOutput, []string{"-p", "udp", "-s", localIP,
				"--sport", localPort, "-j", "ACCEPT", "-w"}},
		}...)
	}

	return r
}

func ensureNetworkSetup(ifm DummyDeviceEnsurer, config nodeCacheConfig, ipt utiliptables.Interface) error {
	exists, err := ifm.EnsureDummyDevice(config.interfaceName)
	if err != nil {
		clog.Errorf("Error ensuring dummy interface %s is present - %s", config.interfaceName, err)
		setupErrCount.WithLabelValues("interface_check").Inc()
		return err
	}

	if !exists {
		clog.Infof("Added interface - %s", config.interfaceName)
	}

	if config.setupIptables {
		for _, rule := range iptablesRules(config.localIPStr, config.localPort) {
			exists, err := ipt.EnsureRule(utiliptables.Prepend, rule.table, rule.chain, rule.args...)
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

func teardownNetworking(ifm DummyDeviceRemover, config nodeCacheConfig, ipt utiliptables.Interface) error {
	clog.Infof("Tearing down")
	if err := ifm.RemoveDummyDevice(config.interfaceName); err != nil {
		clog.Infof("Failed removing interface %s", config.interfaceName)
	}

	if config.setupIptables {
		for _, rule := range iptablesRules(config.localIPStr, config.localPort) {
			clog.Infof("Deleting rule %+v\n", rule)

			if err := ipt.DeleteRule(rule.table, rule.chain, rule.args...); err != nil {
				return err
			}
		}
	}

	return nil
}

func run() {
	config, err := parseAndValidateFlags()
	if err != nil {
		clog.Fatalf("Error parsing flags - %s, Exiting", err)
	}

	ifm := netif.NewNetifManager(config.localIPs)
	ipt := utiliptables.New(utilexec.New(), dbus.New(), utiliptables.ProtocolIpv4)

	caddy.OnProcessExit = append(caddy.OnProcessExit, func() { teardownNetworking(ifm, config, ipt) })

	if err = initMetrics(config.metricsListenAddress); err != nil {
		clog.Fatalf("Error setting up metrics handler - %s, Exiting", err)
	}

	if err = ensureNetworkSetup(ifm, config, ipt); err != nil {
		clog.Fatalf("Error setting up networking - %s, Exiting", err)
	}

	coremain.Run()
}

func main() {
	run()
}
