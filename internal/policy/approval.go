package policy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// ApprovalHandler defines the interface for prompting humans for tool execution approval.
type ApprovalHandler interface {
	RequestApproval(ctx context.Context, toolName string, details string) (bool, error)
}

// ConsoleApprovalHandler prompts the user on /dev/tty or stderr.
type ConsoleApprovalHandler struct {
	mu             sync.Mutex
	timeout        time.Duration
	nonInteractive bool
	ttyReader      io.Reader
	ttyWriter      io.Writer
}

// NewConsoleApprovalHandler constructs an interactive approval handler.
func NewConsoleApprovalHandler(timeoutSec int, nonInteractive bool) *ConsoleApprovalHandler {
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	return &ConsoleApprovalHandler{
		timeout:        time.Duration(timeoutSec) * time.Second,
		nonInteractive: nonInteractive,
	}
}

// SetTTY allows overriding input and output for testing.
func (h *ConsoleApprovalHandler) SetTTY(r io.Reader, w io.Writer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ttyReader = r
	h.ttyWriter = w
}

// RequestApproval displays a prompt and waits for user confirmation (y/N).
func (h *ConsoleApprovalHandler) RequestApproval(ctx context.Context, toolName string, details string) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.nonInteractive {
		return false, fmt.Errorf("non-interactive environment: approval auto-denied")
	}

	reader := h.ttyReader
	writer := h.ttyWriter
	var ttyCloser io.Closer

	// If no custom reader/writer set, try opening /dev/tty
	if reader == nil || writer == nil {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			// Cannot open terminal (e.g. non-interactive subshell), fail safe
			return false, fmt.Errorf("terminal /dev/tty unavailable: approval auto-denied")
		}
		reader = tty
		writer = tty
		ttyCloser = tty
	}

	if ttyCloser != nil {
		defer ttyCloser.Close()
	}

	// Print warning prompt strictly to writer (never os.Stdout)
	fmt.Fprintf(writer, "\n\033[1;33m⚠️  [mcp-jail] Human Approval Required\033[0m\n")
	fmt.Fprintf(writer, "  \033[1mTool:\033[0m    %s\n", toolName)
	if details != "" {
		fmt.Fprintf(writer, "  \033[1mDetails:\033[0m %s\n", details)
	}
	fmt.Fprintf(writer, "  Approve execution? [y/N] (timeout: %ds): ", int(h.timeout.Seconds()))

	type response struct {
		approved bool
		err      error
	}

	respChan := make(chan response, 1)

	go func() {
		scanner := bufio.NewScanner(reader)
		if scanner.Scan() {
			text := strings.TrimSpace(scanner.Text())
			lower := strings.ToLower(text)
			if lower == "y" || lower == "yes" {
				respChan <- response{approved: true, err: nil}
				return
			}
			respChan <- response{approved: false, err: nil}
			return
		}
		if err := scanner.Err(); err != nil {
			respChan <- response{approved: false, err: err}
			return
		}
		respChan <- response{approved: false, err: fmt.Errorf("EOF received")}
	}()

	timer := time.NewTimer(h.timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		fmt.Fprintf(writer, "\n\033[31m[mcp-jail] Approval cancelled.\033[0m\n")
		return false, ctx.Err()
	case <-timer.C:
		fmt.Fprintf(writer, "\n\033[31m[mcp-jail] Approval timed out (default: Deny).\033[0m\n")
		return false, fmt.Errorf("approval request timed out")
	case res := <-respChan:
		if res.approved {
			fmt.Fprintf(writer, "\033[32m[mcp-jail] Approved by user.\033[0m\n\n")
		} else {
			fmt.Fprintf(writer, "\033[31m[mcp-jail] Denied by user.\033[0m\n\n")
		}
		return res.approved, res.err
	}
}
