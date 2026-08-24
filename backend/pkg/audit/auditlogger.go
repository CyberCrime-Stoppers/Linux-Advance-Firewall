package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditEntry represents a single audit log record
type AuditEntry struct {
	Timestamp string `json:"timestamp"`
	User      string `json:"user,omitempty"`
	Action    string `json:"action"`
	Details   string `json:"details"`
	Level     string `json:"level"`
}

// AuditLogger writes append-only audit logs
type AuditLogger struct {
	file   *os.File
	mu     sync.Mutex
	path   string
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(path string) (*AuditLogger, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	return &AuditLogger{file: file, path: path}, nil
}

// Log writes an audit entry
func (a *AuditLogger) Log(action, details, level, user string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	entry := AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		User:      user,
		Action:    action,
		Details:   details,
		Level:     level,
	}

	jsonData, err := json.Marshal(entry)
	if err != nil {
		return
	}

	fmt.Fprintln(a.file, string(jsonData))
}

// Close closes the file descriptor
func (a *AuditLogger) Close() error {
	return a.file.Close()
}
