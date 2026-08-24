package handlers

import (
	"errors"
	"linux-firewall-backend/pkg/audit"
	"linux-firewall-backend/pkg/firewall"
	"linux-firewall-backend/pkg/storage"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type RuleHandler struct {
	store  *storage.RuleStore
	engine *firewall.NftablesEngine
	audit  *audit.AuditLogger
}

func NewRuleHandler(store *storage.RuleStore, engine *firewall.NftablesEngine, audit *audit.AuditLogger) *RuleHandler {
	return &RuleHandler{
		store:  store,
		engine: engine,
		audit:  audit,
	}
}

func (h *RuleHandler) ListRules(c echo.Context) error {
	rules, err := h.store.GetRules()
	if err != nil {
		h.audit.Log("list_rules_failed", err.Error(), "error", getUser(c))
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve rules"})
	}

	summaries := make([]*firewall.RuleSummary, len(rules))
	for i, r := range rules {
		summaries[i] = r.ToSummary()
	}

	return c.JSON(http.StatusOK, summaries)
}

func (h *RuleHandler) GetRule(c echo.Context) error {
	id := c.Param("id")

	rule, err := h.store.GetRule(id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Rule not found"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve rule"})
	}

	return c.JSON(http.StatusOK, rule)
}

func (h *RuleHandler) CreateRule(c echo.Context) error {
	var req struct {
		Name         string `json:"name"`
		Description  string `json:"description"`
		Action       string `json:"action"`
		Protocol     string `json:"protocol"`
		Port         uint16 `json:"port"`
		PortRangeEnd uint16 `json:"port_range_end"`
		Source       string `json:"source"`
		Destination  string `json:"destination"`
		InterfaceIn  string `json:"interface_in"`
		InterfaceOut string `json:"interface_out"`
		Priority     int    `json:"priority"`
	}

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	rule := &firewall.FirewallRule{
		ID:           uuid.New().String(),
		Name:         req.Name,
		Description:  req.Description,
		Action:       firewall.RuleAction(req.Action),
		Protocol:     firewall.Protocol(req.Protocol),
		Port:         req.Port,
		PortRangeEnd: req.PortRangeEnd,
		SourceCIDR:   req.Source,
		DestCIDR:     req.Destination,
		InterfaceIn:  req.InterfaceIn,
		InterfaceOut: req.InterfaceOut,
		Enabled:      true,
		Priority:     req.Priority,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		CreatedBy:    getUser(c),
	}

	if err := rule.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if err := h.engine.ApplyRule(rule); err != nil {
		h.audit.Log("create_rule_apply_failed", rule.ID+": "+err.Error(), "critical", getUser(c))
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to apply rule to firewall engine"})
	}

	if err := h.store.CreateRule(rule); err != nil {
		h.engine.DeleteRule(rule.ID)
		h.audit.Log("create_rule_store_failed", rule.ID+": "+err.Error(), "critical", getUser(c))
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to persist rule"})
	}

	h.audit.Log("create_rule_success", rule.ID, "info", getUser(c))
	return c.JSON(http.StatusCreated, rule)
}

func (h *RuleHandler) UpdateRule(c echo.Context) error {
	id := c.Param("id")

	existing, err := h.store.GetRule(id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Rule not found"})
	}

	var req struct {
		Name         string `json:"name"`
		Description  string `json:"description"`
		Action       string `json:"action"`
		Protocol     string `json:"protocol"`
		Port         uint16 `json:"port"`
		PortRangeEnd uint16 `json:"port_range_end"`
		Source       string `json:"source"`
		Destination  string `json:"destination"`
		InterfaceIn  string `json:"interface_in"`
		InterfaceOut string `json:"interface_out"`
		Priority     int    `json:"priority"`
	}

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.Description != "" {
		existing.Description = req.Description
	}
	if req.Action != "" {
		existing.Action = firewall.RuleAction(req.Action)
	}
	if req.Protocol != "" {
		existing.Protocol = firewall.Protocol(req.Protocol)
	}
	if req.Port > 0 {
		existing.Port = req.Port
	}
	if req.PortRangeEnd > 0 {
		existing.PortRangeEnd = req.PortRangeEnd
	}
	if req.Source != "" {
		existing.SourceCIDR = req.Source
	}
	if req.Destination != "" {
		existing.DestCIDR = req.Destination
	}
	if req.Priority != 0 {
		existing.Priority = req.Priority
	}

	existing.UpdatedAt = time.Now()

	if err := existing.Validate(); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if err := h.engine.ApplyRule(existing); err != nil {
		h.audit.Log("update_rule_apply_failed", id+": "+err.Error(), "critical", getUser(c))
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update rule in firewall engine"})
	}

	if err := h.store.UpdateRule(existing); err != nil {
		h.audit.Log("update_rule_store_failed", id+": "+err.Error(), "critical", getUser(c))
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to persist rule update"})
	}

	h.audit.Log("update_rule_success", id, "info", getUser(c))
	return c.JSON(http.StatusOK, existing)
}

func (h *RuleHandler) DeleteRule(c echo.Context) error {
	id := c.Param("id")

	rule, err := h.store.GetRule(id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Rule not found"})
	}

	if err := h.engine.DeleteRule(id); err != nil {
		h.audit.Log("delete_rule_engine_failed", id+": "+err.Error(), "warning", getUser(c))
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to remove rule from firewall engine"})
	}

	if err := h.store.DeleteRule(id); err != nil {
		h.audit.Log("delete_rule_store_failed", id+": "+err.Error(), "critical", getUser(c))
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to remove rule from storage"})
	}

	h.audit.Log("delete_rule_success", id+" ("+rule.Name+")", "info", getUser(c))
	return c.NoContent(http.StatusNoContent)
}

func (h *RuleHandler) ToggleRule(c echo.Context) error {
	id := c.Param("id")

	var req struct {
		Enabled bool `json:"enabled"`
	}

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Missing 'enabled' field"})
	}

	if err := h.store.ToggleRule(id, req.Enabled); err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Rule not found"})
	}

	rule, _ := h.store.GetRule(id)
	if rule != nil {
		h.engine.ApplyRule(rule)
	}

	h.audit.Log("toggle_rule_success", id+": "+strconv.FormatBool(req.Enabled), "info", getUser(c))
	return c.JSON(http.StatusOK, map[string]bool{"enabled": req.Enabled})
}

func (h *RuleHandler) GetCounts(c echo.Context) error {
	id := c.Param("id")

	if _, err := h.store.GetRule(id); err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Rule not found"})
	}

	counters, err := h.engine.GetCounters()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve counters"})
	}

	if counter, ok := counters[id]; ok {
		return c.JSON(http.StatusOK, counter)
	}

	return c.JSON(http.StatusNotFound, map[string]string{"error": "Counter not available"})
}

func getUser(c echo.Context) string {
	user, ok := c.Get("user").(string)
	if !ok {
		return "unknown"
	}
	return user
}
