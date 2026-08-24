package firewall

// FirewallEngine defines the interface for kernel firewall interaction.
// NftablesEngine (in nftables.go) implements this interface.
type FirewallEngine interface {
	ApplyRule(rule *FirewallRule) error
	DeleteRule(ruleID string) error
	ListRules() (interface{}, error)
	GetCounters() (map[string]*Counter, error)
	Cleanup()
}
