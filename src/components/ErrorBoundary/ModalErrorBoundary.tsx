import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

/**
 * Error boundary specifically for modal content.
 * If a modal crashes (bad form data, undefined props, etc.),
 * we display a safe fallback rather than crashing the entire
 * dashboard — which could leave the firewall in an unmanaged state.
 */
export class ModalErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    // Log to audit system — a crashed modal could indicate
    // corrupted rule data or a malformed API response
    console.error('[MODAL_ERROR]', error, errorInfo);
  }

  render(): ReactNode {
    if (this.state.hasError) {
      // Safe fallback — don't crash the parent app
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="modal-error-fallback">
          <h3>Modal Error</h3>
          <p>
            Something went wrong rendering this panel. The firewall
            is still operating with its current ruleset.
          </p>
          <p className="error-detail">
            {this.state.error?.message}
          </p>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
          >
            Try Again
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
