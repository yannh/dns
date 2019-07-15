package main

import (
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	"testing"
)

func TestIptablesRules(t *testing.T) {
	type testCase struct {
		localIpStr, localPort string
		expectedLen           int
	}

	testCases := []testCase{
		{localIpStr: "192.168.1.100", localPort: "80", expectedLen: 8},
		{localIpStr: "192.168.1.100,192.168.1.101", localPort: "80", expectedLen: 16},
	}

	for _, test := range testCases {
		rules := iptablesRules(test.localIpStr, test.localPort)
		if len(rules) != test.expectedLen {
			t.Errorf("Expected %d iptables rules, got %d", test.expectedLen, len(rules))
		}
	}
}

type mockIptablesEnsurer struct {
	nCalls int
}

func (ipt *mockIptablesEnsurer) EnsureRule(position utiliptables.RulePosition, table utiliptables.Table, chain utiliptables.Chain, args ...string) (bool, error) {
	ipt.nCalls++
	return false, nil
}

func TestEnsureIptablesRulesPresent(t *testing.T) {
	type testCase struct {
		name           string
		rules          []iptablesRule
		expectedRes    error
		expectedNCalls int
	}

	ipt := mockIptablesEnsurer{}

	testCases := []testCase{
		{name: "one listen interface, all rules", rules: iptablesRules("192.168.1.100", "80"), expectedRes: nil, expectedNCalls: 8},
	}

	for _, testCase := range testCases {
		err := ensureIptablesRulesPresent(testCase.rules, &ipt)
		if err != testCase.expectedRes {
			t.Errorf("test %s failed, expected %s, got %s", testCase.name, testCase.expectedRes, err)
		}
		if ipt.nCalls != testCase.expectedNCalls {
			t.Errorf("test %s failed, expected %d calls, got %d", testCase.name, testCase.expectedNCalls, ipt.nCalls)
		}
	}
}
