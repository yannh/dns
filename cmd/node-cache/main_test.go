package main

import (
	"fmt"
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

type mockSuccessfulIptablesEnsurer struct {
	nCalls int
}

func (ipt *mockSuccessfulIptablesEnsurer) EnsureRule(position utiliptables.RulePosition, table utiliptables.Table, chain utiliptables.Chain, args ...string) (bool, error) {
	ipt.nCalls++
	return false, nil
}

func (ipt *mockSuccessfulIptablesEnsurer) invocations() int {
	return ipt.nCalls
}

func (ipt *mockSuccessfulIptablesEnsurer) reset() {
	ipt.nCalls = 0
}

func TestEnsureIptablesRulesPresentSuccesses(t *testing.T) {
	type testCase struct {
		name           string
		rules          []iptablesRule
		ruleEnsurer    mockSuccessfulIptablesEnsurer
		expectedRes    error
		expectedNCalls int
	}

	ipt := mockSuccessfulIptablesEnsurer{}

	testCases := []testCase{
		{
			name:           "one ip, all rules",
			rules:          iptablesRules("192.168.1.100", "80"),
			ruleEnsurer:    ipt,
			expectedRes:    nil,
			expectedNCalls: 8,
		},
		{
			name:           "two ips, all rules",
			rules:          iptablesRules("192.168.1.100,192.168.1.101", "80"),
			ruleEnsurer:    ipt,
			expectedRes:    nil,
			expectedNCalls: 16,
		},
	}

	for _, testCase := range testCases {
		testCase.ruleEnsurer.reset()
		err := ensureIptablesRulesPresent(testCase.rules, &testCase.ruleEnsurer)
		if err != testCase.expectedRes {
			t.Errorf("test '%s' failed, expected %s, got %s", testCase.name, testCase.expectedRes, err)
		}
		if testCase.ruleEnsurer.invocations() != testCase.expectedNCalls {
			t.Errorf("test '%s' failed, expected %d calls, got %d", testCase.name, testCase.expectedNCalls, testCase.ruleEnsurer.invocations())
		}
	}
}

type mockFailingIptablesEnsurer struct {
	nCalls int
}

func (ipt *mockFailingIptablesEnsurer) EnsureRule(position utiliptables.RulePosition, table utiliptables.Table, chain utiliptables.Chain, args ...string) (bool, error) {
	ipt.nCalls++
	if ipt.nCalls%5 == 0 {
		return false, fmt.Errorf("mock error")
	}
	return false, nil
}

func (ipt *mockFailingIptablesEnsurer) reset() {
	ipt.nCalls = 0
}

func TestEnsureIptablesRulesPresentFailures(t *testing.T) {
	type testCase struct {
		name        string
		rules       []iptablesRule
		ruleEnsurer mockFailingIptablesEnsurer
	}

	ipt := mockFailingIptablesEnsurer{}

	testCases := []testCase{
		{
			name:        "one ip, all rules",
			rules:       iptablesRules("192.168.1.100", "80"),
			ruleEnsurer: ipt,
		},
	}

	for _, testCase := range testCases {
		testCase.ruleEnsurer.reset()
		err := ensureIptablesRulesPresent(testCase.rules, &testCase.ruleEnsurer)
		if err == nil {
			t.Errorf("test '%s' failed, expected error, got nil", testCase.name)
		}
	}
}
