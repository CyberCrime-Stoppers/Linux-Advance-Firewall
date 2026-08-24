import { useState } from 'react';
import { FirewallModal } from '../FirewallModal';
import { useModalState } from '../../hooks/useModalState';
import './Dashboard.css';

// Mock rule data — replace with API calls later
interface FirewallRule {
  id: string;
  name: string;
  action: 'ALLOW' | 'DROP';
  protocol: 'TCP' | 'UDP' | 'ICMP';
  port: number;
  source: string;
  destination: string;
  enabled: boolean;
}

const INITIAL_RULES: FirewallRule[] = [
  { id: '1', name: 'ssh-allow', action: 'ALLOW', protocol: 'TCP', port: 22, source: '0.0.0.0/0', destination: '10.0.0.1', enabled: true },
  { id: '2', name: 'http-allow', action: 'ALLOW', protocol: 'TCP', port: 80, source: '0.0.0.0/0', destination: '10.0.0.2', enabled: true },
  { id: '3', name: 'dns-drop', action: 'DROP', protocol: 'UDP', port: 53, source: '192.168.1.50', destination: '8.8.8.8', enabled: false },
];

export function Dashboard() {
  const [rules, setRules] = useState<FirewallRule[]>(INITIAL_RULES);
  const deleteModal = useModalState<FirewallRule>();
  const addModal = useModalState();

  // New rule form state
  const [newRule, setNewRule] = useState({
    name: '',
    action: 'ALLOW' as 'ALLOW' | 'DROP',
    protocol: 'TCP' as 'TCP' | 'UDP' | 'ICMP',
    port: '',
    source: '',
    destination: '',
  });

  const handleDelete = () => {
    if (!deleteModal.data) return;
    setRules(rules.filter(r => r.id !== deleteModal.data!.id));
    deleteModal.close();
  };

  const handleAddRule = () => {
    const rule: FirewallRule = {
      id: crypto.randomUUID(),
      name: newRule.name,
      action: newRule.action,
      protocol: newRule.protocol,
      port: parseInt(newRule.port) || 0,
      source: newRule.source || '0.0.0.0/0',
      destination: newRule.destination || '0.0.0.0/0',
      enabled: true,
    };
    setRules([...rules, rule]);
    setNewRule({ name: '', action: 'ALLOW', protocol: 'TCP', port: '', source: '', destination: '' });
    addModal.close();
  };

  const toggleRule = (id: string) => {
    setRules(rules.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
  };

  return (
    <div className="dashboard">
      {/* ===== Sidebar ===== */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <span className="logo-icon">🛡</span>
          <span className="logo-text">SentinelFW</span>
        </div>
        <nav className="sidebar-nav">
          <a className="nav-item active">Rules</a>
          <a className="nav-item">Traffic Monitor</a>
          <a className="nav-item">Logs</a>
          <a className="nav-item">Threat Intel</a>
          <a className="nav-item">Settings</a>
        </nav>
        <div className="sidebar-footer">
          <div className="status-pill online">
            <span className="status-dot" />
            Firewall Active
          </div>
        </div>
      </aside>

      {/* ===== Main Content ===== */}
      <main className="main-content">
        {/* Header */}
        <header className="content-header">
          <div>
            <h1>Firewall Rules</h1>
            <p className="header-subtitle">{rules.length} rules · {rules.filter(r => r.enabled).length} active</p>
          </div>
          <button className="add-rule-btn" onClick={() => addModal.open()}>
            + Add Rule
          </button>
        </header>

        {/* Stats Bar */}
        <div className="stats-bar">
          <div className="stat-card">
            <span className="stat-value">{rules.length}</span>
            <span className="stat-label">Total Rules</span>
          </div>
          <div className="stat-card">
            <span className="stat-value">{rules.filter(r => r.action === 'ALLOW').length}</span>
            <span className="stat-label">Allow</span>
          </div>
          <div className="stat-card">
            <span className="stat-value danger">{rules.filter(r => r.action === 'DROP').length}</span>
            <span className="stat-label">Drop</span>
          </div>
          <div className="stat-card">
            <span className="stat-value warning">{rules.filter(r => !r.enabled).length}</span>
            <span className="stat-label">Disabled</span>
          </div>
        </div>

        {/* Rules Table */}
        <div className="rules-table-container">
          <table className="rules-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Name</th>
                <th>Action</th>
                <th>Protocol</th>
                <th>Port</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id} className={!rule.enabled ? 'row-disabled' : ''}>
                  <td>
                    <label className="toggle-switch">
                      <input
                        type="checkbox"
                        checked={rule.enabled}
                        onChange={() => toggleRule(rule.id)}
                      />
                      <span className="toggle-slider" />
                    </label>
                  </td>
                  <td><code>{rule.name}</code></td>
                  <td>
                    <span className={`action-badge action-${rule.action.toLowerCase()}`}>
                      {rule.action}
                    </span>
                  </td>
                  <td>{rule.protocol}</td>
                  <td><code>{rule.port}</code></td>
                  <td><code>{rule.source}</code></td>
                  <td><code>{rule.destination}</code></td>
                  <td>
                    <button
                      className="delete-btn"
                      onClick={() => deleteModal.open(rule)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>

      {/* ===== Delete Confirmation Modal ===== */}
      <FirewallModal
        isOpen={deleteModal.isOpen}
        onClose={deleteModal.close}
        title="Delete Firewall Rule"
        description="This rule will be removed from the active ruleset immediately. Affected traffic will be evaluated against remaining rules."
        variant="confirmation"
        severity="warning"
        width="md"
        confirmation={{
          typeToConfirm: deleteModal.data?.name || '',
          confirmLabel: `Type the rule name to confirm deletion`,
        }}
        buttons={[
          { label: 'Cancel', variant: 'secondary', onClick: deleteModal.close },
          { label: 'Delete Rule', variant: 'danger', onClick: handleDelete },
        ]}
      >
        <div className="rule-preview">
          <div className="preview-row">
            <span>Rule:</span>
            <code>{deleteModal.data?.name}</code>
          </div>
          <div className="preview-row">
            <span>Action:</span>
            <span className={`action-badge action-${deleteModal.data?.action.toLowerCase()}`}>
              {deleteModal.data?.action}
            </span>
          </div>
          <div className="preview-row">
            <span>Protocol:</span>
            <code>{deleteModal.data?.protocol} / {deleteModal.data?.port}</code>
          </div>
          <div className="preview-row">
            <span>Source:</span>
            <code>{deleteModal.data?.source}</code>
          </div>
          <div className="preview-row">
            <span>Destination:</span>
            <code>{deleteModal.data?.destination}</code>
          </div>
        </div>
      </FirewallModal>

      {/* ===== Add Rule Modal ===== */}
      <FirewallModal
        isOpen={addModal.isOpen}
        onClose={addModal.close}
        title="Create Firewall Rule"
        description="Define a new rule for packet filtering. The rule will be applied immediately upon creation."
        variant="form"
        severity="info"
        width="lg"
        buttons={[
          { label: 'Cancel', variant: 'secondary', onClick: addModal.close },
          {
            label: 'Create Rule',
            variant: 'primary',
            onClick: handleAddRule,
            disabled: !newRule.name || !newRule.port,
          },
        ]}
      >
        <div className="rule-form">
          <div className="form-row">
            <label>Rule Name</label>
            <input
              type="text"
              placeholder="e.g. block-ssh-bruteforce"
              value={newRule.name}
              onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
              className="form-input"
            />
          </div>

          <div className="form-row-grid">
            <div className="form-row">
              <label>Action</label>
              <select
                value={newRule.action}
                onChange={(e) => setNewRule({ ...newRule, action: e.target.value as 'ALLOW' | 'DROP' })}
                className="form-select"
              >
                <option value="ALLOW">ALLOW</option>
                <option value="DROP">DROP</option>
              </select>
            </div>
            <div className="form-row">
              <label>Protocol</label>
              <select
                value={newRule.protocol}
                onChange={(e) => setNewRule({ ...newRule, protocol: e.target.value as 'TCP' | 'UDP' | 'ICMP' })}
                className="form-select"
              >
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>
            </div>
            <div className="form-row">
              <label>Port</label>
              <input
                type="number"
                placeholder="22"
                value={newRule.port}
                onChange={(e) => setNewRule({ ...newRule, port: e.target.value })}
                className="form-input"
              />
            </div>
          </div>

          <div className="form-row-grid">
            <div className="form-row">
              <label>Source IP / CIDR</label>
              <input
                type="text"
                placeholder="0.0.0.0/0"
                value={newRule.source}
                onChange={(e) => setNewRule({ ...newRule, source: e.target.value })}
                className="form-input"
              />
            </div>
            <div className="form-row">
              <label>Destination IP / CIDR</label>
              <input
                type="text"
                placeholder="10.0.0.1"
                value={newRule.destination}
                onChange={(e) => setNewRule({ ...newRule, destination: e.target.value })}
                className="form-input"
              />
            </div>
          </div>
        </div>
      </FirewallModal>
    </div>
  );
}
