import type { ReactNode } from 'react';

// ===== Severity Levels =====
export type ModalSeverity = 'info' | 'warning' | 'critical';

// ===== Modal Variants =====
export type ModalVariant =
| 'confirmation'   // Yes/No dialogs
| 'form'           // Rule creation/editing
| 'alert'          // Intrusion notifications
| 'credential';    // Password/token entry

// ===== Button Configuration =====
export interface ModalButton {
    label: string;
    variant?: 'primary' | 'secondary' | 'danger';
    onClick: () => void;
    disabled?: boolean;
    loading?: boolean;
}

// ===== Confirmation-Specific Props =====
export interface ConfirmationConfig {
    /** Text the user must type to enable the confirm button */
    typeToConfirm?: string;
    /** Label for the confirmation input */
    confirmLabel?: string;
}

// ===== Form-Specific Props =====
export interface FormConfig {
    /** Show dry-run simulation results before submitting */
    enableDryRun?: boolean;
    /** Callback fired when user clicks "Simulate" */
    onDryRun?: (formData: Record<string, unknown>) => Promise<DryRunResult>;
}

// ===== Dry Run Results =====
export interface DryRunResult {
    status: 'pass' | 'fail' | 'warning';
    matchedRules: number;
    droppedPackets: number;
    allowedPackets: number;
    details: string[];
}

// ===== Alert-Specific Props =====
export interface AlertConfig {
    sourceIp?: string;
    destinationIp?: string;
    port?: number;
    protocol?: 'TCP' | 'UDP' | 'ICMP';
    timestamp: string;
    acknowledged: boolean;
}

// ===== Credential-Specific Props =====
export interface CredentialConfig {
    authType: 'password' | 'token' | 'mfa';
    /** Session timeout in seconds before re-auth is required */
    sessionTimeout: number;
}

// ===== Main Component Props =====
export interface FirewallModalProps {
    /** Controls visibility */
    isOpen: boolean;

    /** Called when user requests close (ESC, overlay click, cancel) */
    onClose: () => void;

    /** Modal title displayed in header */
    title: string;

    /** Subtitle or context description */
    description?: string;

    /** Which visual variant to render */
    variant: ModalVariant;

    /** Severity level — affects color and urgency */
    severity?: ModalSeverity;

    /** Modal body content */
    children: ReactNode;

    /** Action buttons rendered in footer */
    buttons: ModalButton[];

    /** Variant-specific configuration */
    confirmation?: ConfirmationConfig;
    form?: FormConfig;
    alert?: AlertConfig;
    credential?: CredentialConfig;

    /** Disable closing via overlay click (force explicit button press) */
    disableOverlayClose?: boolean;

    /** Width preset */
    width?: 'sm' | 'md' | 'lg' | 'xl';

    /** Custom class for styling overrides */
    className?: string;
}
