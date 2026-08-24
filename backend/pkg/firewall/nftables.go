package firewall

import (
	"context"
	"fmt"
	"log"
	"net"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

type NftablesEngine struct {
	conn   *nftables.Conn
	table  *nftables.Table
	family nftables.TableFamily   // ← Remove the * (asterisk)
	chain  *nftables.Chain
	ctx    context.Context          // ← Remove the * (asterisk)
}

func NewNftablesEngine(ctx context.Context) (*NftablesEngine, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to nftables: %w", err)
	}

	e := &NftablesEngine{
		conn:   conn,
		family: nftables.TableFamilyIPv4,
		ctx:    ctx,
	}

	tables, _ := conn.ListTables()
	found := false
	for _, t := range tables {
		if t.Name == "sentinel_fw" && t.Family == e.family {
			e.table = t
			found = true
			break
		}
	}

	if !found {
		e.table = conn.AddTable(&nftables.Table{
			Name:   "sentinel_fw",
			Family: e.family,
		})
		if err := conn.Flush(); err != nil {
			return nil, fmt.Errorf("failed to create table: %w", err)
		}
		log.Println("[NFTables] Created sentinel_fw table")
	}

	chains, _ := conn.ListChainsOfTableFamily(e.family)
	for _, c := range chains {
		if c.Table.Name == "sentinel_fw" && c.Name == "forward_chain" {
			e.chain = c
			break
		}
	}

	if e.chain == nil {
		policy := nftables.ChainPolicyDrop
		priority := nftables.ChainPriority(0)

		e.chain = conn.AddChain(&nftables.Chain{
			Name:     "forward_chain",
			Table:    e.table,
			Type:     "filter",
			Hooknum:  nftables.ChainHookForward,
			Priority: &priority,
			Policy:   &policy,
		})
		if err := conn.Flush(); err != nil {
			return nil, fmt.Errorf("failed to create chain: %w", err)
		}
		log.Println("[NFTables] Created forward_chain with default drop policy")
	}

	return e, nil
}

func (e *NftablesEngine) ApplyRule(rule *FirewallRule) error {
	rules, err := e.conn.GetRules(e.table, e.chain)
	if err != nil {
		return fmt.Errorf("failed to get rules: %w", err)
	}

	var ruleIndex int = -1
	for i, r := range rules {
		if metadata, ok := getRuleMetadata(r); ok {
			if metadata.RuleID == rule.ID {
				ruleIndex = i
				break
			}
		}
	}

	if ruleIndex >= 0 {
		if err := e.conn.DelRule(rules[ruleIndex]); err != nil {
			return fmt.Errorf("failed to delete old rule: %w", err)
		}
	}

	if rule.Enabled {
		nftRules, err := e.buildNftablesExpressions(rule)
		if err != nil {
			return fmt.Errorf("failed to build expressions: %w", err)
		}

		newRule := &nftables.Rule{
			Table:    e.table,
			Chain:    e.chain,
			Position: uint64(rule.Priority),
			Exprs:    nftRules,
		}

		setRuleMetadata(newRule, rule.ID)
		e.conn.AddRule(newRule)
	}

	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush changes: %w", err)
	}

	log.Printf("[NFTables] Applied rule: %s (ID: %s)\n", rule.Name, rule.ID)
	return nil
}

func (e *NftablesEngine) DeleteRule(ruleID string) error {
	rules, err := e.conn.GetRules(e.table, e.chain)
	if err != nil {
		return fmt.Errorf("failed to get rules: %w", err)
	}

	var targetRule *nftables.Rule
	for _, r := range rules {
		if metadata, ok := getRuleMetadata(r); ok {
			if metadata.RuleID == ruleID {
				targetRule = r
				break
			}
		}
	}

	if targetRule == nil {
		return fmt.Errorf("rule not found: %s", ruleID)
	}

	if err := e.conn.DelRule(targetRule); err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush changes: %w", err)
	}

	log.Printf("[NFTables] Deleted rule: %s\n", ruleID)
	return nil
}

func (e *NftablesEngine) ListRules() (interface{}, error) {
	return e.conn.GetRules(e.table, e.chain)
}

func (e *NftablesEngine) GetCounters() (map[string]*Counter, error) {
	rules, err := e.conn.GetRules(e.table, e.chain)
	if err != nil {
		return nil, err
	}

	counters := make(map[string]*Counter)
	for _, r := range rules {
		if metadata, ok := getRuleMetadata(r); ok {
			counter := &Counter{
				RuleID:  metadata.RuleID,
				Packets: 0,
				Bytes:   0,
			}

			for _, e := range r.Exprs {
				if counterExpr, ok := e.(*expr.Counter); ok {
					counter.Packets = counterExpr.Packets
					counter.Bytes = counterExpr.Bytes
				}
			}

			counters[metadata.RuleID] = counter
		}
	}

	return counters, nil
}

func (e *NftablesEngine) Cleanup() {
	// Connection doesn't need explicit close in nftables lib
}

func (e *NftablesEngine) buildNftablesExpressions(rule *FirewallRule) ([]expr.Any, error) {
	var exprs []expr.Any

	// Match protocol
	var proto uint8
	switch rule.Protocol {
		case ProtoTCP:
			proto = 6
		case ProtoUDP:
			proto = 17
		case ProtoICMP:
			proto = 1
		default:
			proto = 0
	}

	if proto != 0 {
		exprs = append(exprs, &expr.Meta{
			Key:      expr.MetaKeyPROTOCOL,
			Register: 1,
		})
		exprs = append(exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{proto, 0, 0, 0},
		})
	}

	// Match source CIDR
	srcIP, srcNet, err := net.ParseCIDR(rule.SourceCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid source CIDR: %w", err)
	}
	srcMask := srcNet.Mask

	exprs = append(exprs, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       12,
		Len:          4,
	})
	exprs = append(exprs, &expr.Bitwise{
		SourceRegister: 1,
		DestRegister:   1,
		Len:            4,
		Mask:           srcMask,
		Xor:            []byte{0, 0, 0, 0},
	})
	exprs = append(exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     srcIP.To4(),
	})

	// Match destination CIDR
	dstIP, dstNet, err := net.ParseCIDR(rule.DestCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid destination CIDR: %w", err)
	}
	dstMask := dstNet.Mask

	exprs = append(exprs, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       16,
		Len:          4,
	})
	exprs = append(exprs, &expr.Bitwise{
		SourceRegister: 1,
		DestRegister:   1,
		Len:            4,
		Mask:           dstMask,
		Xor:            []byte{0, 0, 0, 0},
	})
	exprs = append(exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     dstIP.To4(),
	})

	// Match port
	if rule.Port > 0 && (rule.Protocol == ProtoTCP || rule.Protocol == ProtoUDP) {
		portBytes := binaryutil.BigEndian.PutUint16(uint16(rule.Port))

		exprs = append(exprs, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       0,
			Len:          2,
		})
		exprs = append(exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     portBytes,
		})
	}

	// Final action
	if rule.Action == ActionAllow {
		exprs = append(exprs, &expr.Verdict{
			Kind: expr.VerdictAccept,
		})
	} else {
		exprs = append(exprs, &expr.Verdict{
			Kind: expr.VerdictDrop,
		})
	}

	return exprs, nil
}

type ruleMetadata struct {
	RuleID string
}

func getRuleMetadata(r *nftables.Rule) (ruleMetadata, bool) {
	return ruleMetadata{}, false
}

func setRuleMetadata(r *nftables.Rule, ruleID string) {
}
