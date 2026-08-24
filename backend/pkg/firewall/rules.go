package firewall

import (
	"fmt"
	"net"
	"time"
)

type RuleAction string

const (
	ActionAllow  RuleAction = "ALLOW"
	ActionDrop   RuleAction = "DROP"
	ActionReject RuleAction = "REJECT"
)

type Protocol string

const (
	ProtoTCP  Protocol = "TCP"
	ProtoUDP  Protocol = "UDP"
	ProtoICMP Protocol = "ICMP"
	ProtoAny  Protocol = "ANY"
)

type FirewallRule struct {
	ID           string     `json:"id" gorm:"primaryKey"`
	Name         string     `json:"name" validate:"required,min=2,max=64"`
	Description  string     `json:"description,omitempty" gorm:"size:256"`
	Action       RuleAction `json:"action" validate:"required,oneof=ALLOW DROP REJECT"`
	Protocol     Protocol   `json:"protocol" validate:"required,oneof=TCP UDP ICMP ANY"`
	Port         uint16     `json:"port" validate:"omitempty,lte=65535"`
	PortRangeEnd uint16     `json:"port_range_end,omitempty"`
	SourceCIDR   string     `json:"source" validate:"required,cidr"`
	DestCIDR     string     `json:"destination" validate:"required,cidr"`
	InterfaceIn  string     `json:"interface_in,omitempty" gorm:"size:32"`
	InterfaceOut string     `json:"interface_out,omitempty" gorm:"size:32"`
	Enabled      bool       `json:"enabled"`
	Priority     int        `json:"priority" gorm:"default:100"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	CreatedBy    string     `json:"created_by"`
}

type RuleSummary struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Action     RuleAction `json:"action"`
	Protocol   Protocol   `json:"protocol"`
	Port       uint16     `json:"port"`
	SourceCIDR string     `json:"source"`
	DestCIDR   string     `json:"destination"`
	Enabled    bool       `json:"enabled"`
	Priority   int        `json:"priority"`
}

type Counter struct {
	RuleID  string
	Packets uint64
	Bytes   uint64
}

func (r *FirewallRule) ToSummary() *RuleSummary {
	return &RuleSummary{
		ID:         r.ID,
		Name:       r.Name,
		Action:     r.Action,
		Protocol:   r.Protocol,
		Port:       r.Port,
		SourceCIDR: r.SourceCIDR,
		DestCIDR:   r.DestCIDR,
		Enabled:    r.Enabled,
		Priority:   r.Priority,
	}
}

func (r *FirewallRule) Validate() error {
	if len(r.Name) < 2 || len(r.Name) > 64 {
		return fmt.Errorf("rule name must be between 2 and 64 characters")
	}
	if !IsValidCIDR(r.SourceCIDR) {
		return fmt.Errorf("invalid source CIDR format")
	}
	if !IsValidCIDR(r.DestCIDR) {
		return fmt.Errorf("invalid destination CIDR format")
	}
	if r.Port > 65535 {
		return fmt.Errorf("port must be between 0 and 65535")
	}
	return nil
}

func IsValidCIDR(cidr string) bool {
	if cidr == "" {
		return false
	}
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}
