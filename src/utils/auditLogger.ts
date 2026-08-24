/**
 * Lightweight audit logger for security-critical modal actions.
 * In production, this should write to an append-only store or ship
 * to a remote syslog server. Never buffer in memory alone.
 */

export type AuditAction =
  | 'modal_opened'
  | 'modal_closed'
  | 'rule_deleted'
  | 'rule_created'
  | 'rule_modified'
  | 'dry_run_executed'
  | 'credential_entered'
  | 'alert_acknowledged'
  | 'confirmation_typed';

interface AuditEntry {
  timestamp: string;
  action: AuditAction;
  detail: string;
  user?: string;
  severity: 'info' | 'warning' | 'critical';
}

class AuditLogger {
  private buffer: AuditEntry[] = [];
  private flushInterval: ReturnType<typeof setInterval>;

  constructor(flushMs: number = 5000) {
    // Flush to backend every 5 seconds
    this.flushInterval = setInterval(() => this.flush(), flushMs);
  }

  log(action: AuditAction, detail: string, severity: 'info' | 'warning' | 'critical' = 'info', user?: string): void {
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      action,
      detail,
      severity,
      user,
    };
    this.buffer.push(entry);
  }

  private async flush(): Promise<void> {
    if (this.buffer.length === 0) return;

    const entries = [...this.buffer];
    this.buffer = [];

    try {
      // Replace with your actual API endpoint
      await fetch('/api/v1/audit/log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entries }),
        // Use include for cookie-based session auth
        credentials: 'include',
      });
    } catch (err) {
      // Re-buffer on failure — never lose audit entries
      console.error('[AUDIT] Failed to flush, re-buffering:', err);
      this.buffer.unshift(...entries);
    }
  }

  destroy(): void {
    clearInterval(this.flushInterval);
    this.flush();
  }
}

export const auditLogger = new AuditLogger();
