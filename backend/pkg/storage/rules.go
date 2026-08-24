package storage

import (
	"errors"
	"fmt"
	"time"

	"linux-firewall-backend/pkg/firewall"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var ErrNotFound = errors.New("rule not found")

// ... rest of storage code ...

type RuleStore struct {
	db *gorm.DB
}

func NewRuleStore(dbPath string) (*RuleStore, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.AutoMigrate(&StoredRule{}); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return &RuleStore{db: db}, nil
}

type StoredRule struct {
	ID           string    `gorm:"primaryKey"`
	Name         string    `gorm:"size:64;not null"`
	Description  string    `gorm:"size:256"`
	Action       string    `gorm:"size:8;not null"`
	Protocol     string    `gorm:"size:8;not null"`
	Port         uint16
	PortRangeEnd uint16
	SourceCIDR   string    `gorm:"size:45;not null"`
	DestCIDR     string    `gorm:"size:45;not null"`
	InterfaceIn  string    `gorm:"size:32"`
	InterfaceOut string    `gorm:"size:32"`
	Enabled      bool      `gorm:"default:true"`
	Priority     int       `gorm:"default:100"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	CreatedBy    string    `gorm:"size:64"`
}

func (s *StoredRule) toFirewallRule() *firewall.FirewallRule {
	return &firewall.FirewallRule{
		ID:           s.ID,
		Name:         s.Name,
		Description:  s.Description,
		Action:       firewall.RuleAction(s.Action),
		Protocol:     firewall.Protocol(s.Protocol),
		Port:         s.Port,
		PortRangeEnd: s.PortRangeEnd,
		SourceCIDR:   s.SourceCIDR,
		DestCIDR:     s.DestCIDR,
		InterfaceIn:  s.InterfaceIn,
		InterfaceOut: s.InterfaceOut,
		Enabled:      s.Enabled,
		Priority:     s.Priority,
		CreatedAt:    s.CreatedAt,
		UpdatedAt:    s.UpdatedAt,
		CreatedBy:    s.CreatedBy,
	}
}

func fromFirewallRule(r *firewall.FirewallRule) *StoredRule {
	return &StoredRule{
		ID:           r.ID,
		Name:         r.Name,
		Description:  r.Description,
		Action:       string(r.Action),
		Protocol:     string(r.Protocol),
		Port:         r.Port,
		PortRangeEnd: r.PortRangeEnd,
		SourceCIDR:   r.SourceCIDR,
		DestCIDR:     r.DestCIDR,
		InterfaceIn:  r.InterfaceIn,
		InterfaceOut: r.InterfaceOut,
		Enabled:      r.Enabled,
		Priority:     r.Priority,
		CreatedBy:    r.CreatedBy,
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
	}
}

func (s *RuleStore) CreateRule(rule *firewall.FirewallRule) error {
	stored := fromFirewallRule(rule)
	stored.ID = rule.ID
	result := s.db.Create(stored)
	return result.Error
}

func (s *RuleStore) GetRule(id string) (*firewall.FirewallRule, error) {
	var stored StoredRule
	result := s.db.First(&stored, "id = ?", id)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, ErrNotFound
		}
		return nil, result.Error
	}
	return stored.toFirewallRule(), nil
}

func (s *RuleStore) GetRules() ([]*firewall.FirewallRule, error) {
	var stored []StoredRule
	result := s.db.Order("priority ASC").Find(&stored)
	if result.Error != nil {
		return nil, result.Error
	}

	rules := make([]*firewall.FirewallRule, len(stored))
	for i, sr := range stored {
		rules[i] = sr.toFirewallRule()
	}
	return rules, nil
}

func (s *RuleStore) UpdateRule(rule *firewall.FirewallRule) error {
	stored := fromFirewallRule(rule)
	stored.UpdatedAt = time.Now()
	result := s.db.Save(stored)
	return result.Error
}

func (s *RuleStore) DeleteRule(id string) error {
	result := s.db.Delete(&StoredRule{}, "id = ?", id)
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return result.Error
}

func (s *RuleStore) ToggleRule(id string, enabled bool) error {
	result := s.db.Model(&StoredRule{}).Where("id = ?", id).Update("enabled", enabled)
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return result.Error
}
