import { useRef, useState, type ReactNode } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { useFocusTrap } from '../../hooks/useFocusTrap';
import { auditLogger } from '../../utils/auditLogger';
import { ModalErrorBoundary } from '../ErrorBoundary/ModalErrorBoundary';
import type {
  FirewallModalProps,
  DryRunResult,
} from './FirewallModal.types';

const WIDTH_MAP = {
  sm: '400px',
  md: '520px',
  lg: '680px',
  xl: '900px',
} as const;

export function FirewallModal({
  isOpen,
  onClose,
  title,
  description,
  variant,
  severity = 'info',
  children,
  buttons,
  confirmation,
  form,
  alert,
  credential,
  disableOverlayClose = false,
  width = 'md',
  className = '',
}: FirewallModalProps) {
  const contentRef = useRef<HTMLDivElement>(null);
  const [confirmText, setConfirmText] = useState('');
  const [dryRunResult, setDryRunResult] = useState<DryRunResult | null>(null);
  const [isDryRunning, setIsDryRunning] = useState(false);

  useFocusTrap(contentRef, isOpen);

  // ---- Confirmation Logic ----
  const isConfirmed = !confirmation?.typeToConfirm
    || confirmText === confirmation.typeToConfirm;

  // ---- Handle Close with Audit ----
  const handleClose = (reason: 'overlay' | 'escape' | 'button') => {
    if (disableOverlayClose && reason === 'overlay') return;
    auditLogger.log('modal_closed', `${variant}:${title} via ${reason}`, severity);
    setConfirmText('');
    setDryRunResult(null);
    onClose();
  };

  // ---- Dry Run Handler ----
  const handleDryRun = async () => {
    if (!form?.onDryRun) return;
    setIsDryRunning(true);
    try {
      // Caller passes form data from their own state
      const result = await form.onDryRun({});
      setDryRunResult(result);
      auditLogger.log('dry_run_executed', `${title}: ${result.status}`, 'info');
    } catch (err) {
      setDryRunResult({
        status: 'fail',
        matchedRules: 0,
        droppedPackets: 0,
        allowedPackets: 0,
        details: [`Error: ${err instanceof Error ? err.message : 'Unknown'}`],
      });
    } finally {
      setIsDryRunning(false);
    }
  };

  // ---- Severity Styling ----
  const severityClass = `severity-${severity}`;
  const widthStyle = { maxWidth: WIDTH_MAP[width] };

  return (
    <Dialog.Root
      open={isOpen}
      onOpenChange={(open) => !open && handleClose('overlay')}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="firewall-modal-overlay" />
        <Dialog.Content
          ref={contentRef}
          className={`firewall-modal ${severityClass} ${className}`}
          style={widthStyle}
          onEscapeKeyDown={() => handleClose('escape')}
        >
          {/* ===== Header ===== */}
          <div className="firewall-modal-header">
            <div className="header-left">
              {severity === 'critical' && (
                <span className="severity-indicator" aria-hidden="true">
                  ⚠
                </span>
              )}
              <Dialog.Title className="firewall-modal-title">
                {title}
              </Dialog.Title>
            </div>
            <button
              className="firewall-modal-close"
              onClick={() => handleClose('button')}
              aria-label="Close dialog"
            >
              ✕
            </button>
          </div>

          {description && (
            <Dialog.Description className="firewall-modal-description">
              {description}
            </Dialog.Description>
          )}

          {/* ===== Alert Metadata (if applicable) ===== */}
          {variant === 'alert' && alert && (
            <div className="alert-metadata">
              {alert.sourceIp && (
                <div className="metadata-row">
                  <span className="metadata-label">Source:</span>
                  <code>{alert.sourceIp}</code>
                </div>
              )}
              {alert.destinationIp && (
                <div className="metadata-row">
                  <span className="metadata-label">Destination:</span>
                  <code>{alert.destinationIp}</code>
                </div>
              )}
              {alert.port && (
                <div className="metadata-row">
                  <span className="metadata-label">Port:</span>
                  <code>{alert.port}/{alert.protocol}</code>
                </div>
              )}
              <div className="metadata-row">
                <span className="metadata-label">Time:</span>
                <code>{alert.timestamp}</code>
              </div>
            </div>
          )}

          {/* ===== Body (wrapped in error boundary) ===== */}
          <ModalErrorBoundary>
            <div className="firewall-modal-body">
              {children}

              {/* Confirmation Input */}
              {variant === 'confirmation' && confirmation?.typeToConfirm && (
                <div className="confirm-input-group">
                  <label htmlFor="confirm-input">
                    {confirmation.confirmLabel
                      || `Type "${confirmation.typeToConfirm}" to confirm`}
                  </label>
                  <input
                    id="confirm-input"
                    type="text"
                    value={confirmText}
                    onChange={(e) => setConfirmText(e.target.value)}
                    autoComplete="off"
                    spellCheck={false}
                    className="confirm-input"
                  />
                </div>
              )}

              {/* Dry Run Results */}
              {form?.enableDryRun && dryRunResult && (
                <div className={`dry-run-result dry-run-${dryRunResult.status}`}>
                  <h4>Dry Run Simulation</h4>
                  <div className="dry-run-stats">
                    <span>Matched: {dryRunResult.matchedRules}</span>
                    <span>Allowed: {dryRunResult.allowedPackets}</span>
                    <span>Dropped: {dryRunResult.droppedPackets}</span>
                  </div>
                  {dryRunResult.details.length > 0 && (
                    <ul className="dry-run-details">
                      {dryRunResult.details.map((detail, i) => (
                        <li key={i}>{detail}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </div>
          </ModalErrorBoundary>

          {/* ===== Footer / Actions ===== */}
          <div className="firewall-modal-footer">
            {/* Dry Run button (if enabled) */}
            {form?.enableDryRun && (
              <button
                className="btn btn-secondary"
                onClick={handleDryRun}
                disabled={isDryRunning}
              >
                {isDryRunning ? 'Simulating...' : 'Dry Run'}
              </button>
            )}

            {/* Standard buttons */}
            {buttons.map((btn, idx) => (
              <button
                key={idx}
                className={`btn btn-${btn.variant || 'secondary'}`}
                onClick={btn.onClick}
                disabled={btn.disabled || (btn.variant === 'danger' && !isConfirmed)}
                aria-disabled={btn.disabled}
              >
                {btn.loading ? '...' : btn.label}
              </button>
            ))}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
