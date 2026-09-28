package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Approval mechanism for the demo's make-credential / get-assertion / U2F
// callbacks.
//
// By default this is the original interactive terminal Y/n prompt. It can be
// redirected — without code changes — via environment variables, so the demo
// can be confirmed by an external device (a hardware button, a notification
// daemon, a phone push, etc.) instead of the terminal:
//
//	VFIDO_APPROVE_CMD        Shell command run (via `sh -c`) for each approval.
//	                         Receives the action description as $1, also exported
//	                         as $VFIDO_APPROVE_ACTION. Exiting 0 within the
//	                         timeout approves; non-zero or timeout denies.
//	VFIDO_APPROVE_FIFO       Path to a FIFO; approval is granted when a line
//	                         containing "y" is read from it before the timeout.
//	VFIDO_APPROVE_NOTIFY_CMD Optional command run (via `sh -c`) at the start and
//	                         end of every approval wait, receiving "begin"/"end"
//	                         as $1 and the description as $2. Handy to drive an
//	                         LED or on-screen hint while waiting.
//	VFIDO_APPROVE_TIMEOUT    Approval timeout in seconds (default 20; 0 = wait
//	                         forever).
//
// Resolution order: VFIDO_APPROVE_CMD, then VFIDO_APPROVE_FIFO, then the
// terminal prompt.

const defaultApprovalTimeout = 20 * time.Second

func approvalTimeout() time.Duration {
	if v := os.Getenv("VFIDO_APPROVE_TIMEOUT"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return defaultApprovalTimeout
}

// runHook runs cmd via `sh -c`, passing args as the positional parameters
// $1, $2, ... (so descriptions containing spaces/quotes can't be re-parsed by
// the shell). Failures are ignored — notifications are best-effort.
func runHook(cmd string, args ...string) {
	if cmd == "" {
		return
	}
	argv := append([]string{"-c", cmd + ` "$@"`, "sh"}, args...)
	_ = exec.Command("sh", argv...).Run()
}

// approveAction resolves a single approval for a human-readable action. It
// gives up (denies) as soon as ctx is cancelled, i.e. when the browser cancels
// the request or the device is detached.
func approveAction(ctx context.Context, description string) bool {
	if notify := os.Getenv("VFIDO_APPROVE_NOTIFY_CMD"); notify != "" {
		runHook(notify, "begin", description)
		defer runHook(notify, "end", description)
	}
	timeout := approvalTimeout()
	switch {
	case os.Getenv("VFIDO_APPROVE_CMD") != "":
		return runApproveCmd(ctx, os.Getenv("VFIDO_APPROVE_CMD"), description, timeout)
	case os.Getenv("VFIDO_APPROVE_FIFO") != "":
		return waitFifoApproval(ctx, description, timeout)
	default:
		return prompt(ctx, fmt.Sprintf("Approve %s (Y/n)?", description))
	}
}

// runApproveCmd runs an external approval command; exit 0 within the timeout
// approves.
func runApproveCmd(ctx context.Context, cmd, description string, timeout time.Duration) bool {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	fmt.Printf("\n>>> %s\n>>> awaiting approval via VFIDO_APPROVE_CMD ...\n", description)
	c := exec.CommandContext(ctx, "sh", "-c", cmd+` "$@"`, "sh", description)
	c.Env = append(os.Environ(), "VFIDO_APPROVE_ACTION="+description)
	if err := c.Run(); err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Println(">>> CANCELLED by the host")
		} else {
			fmt.Printf(">>> DENIED (%v)\n", err)
		}
		return false
	}
	fmt.Println(">>> APPROVED")
	return true
}

// --- FIFO approval -------------------------------------------------------

var approvalCh = make(chan struct{}, 16)

// startApprovalListener keeps the FIFO's read end open for the whole process
// (so writers never block) and forwards each "y" to approvalCh. It is a no-op
// unless VFIDO_APPROVE_FIFO is set.
func startApprovalListener() {
	path := os.Getenv("VFIDO_APPROVE_FIFO")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		fmt.Printf("[approval] WARNING: cannot open FIFO %s: %s (FIFO approvals disabled)\n", path, err)
		return
	}
	fmt.Printf("[approval] FIFO approval enabled (%s)\n", path)
	go func() {
		buf := make([]byte, 64)
		for {
			n, err := f.Read(buf)
			if n > 0 && strings.Contains(strings.ToLower(string(buf[:n])), "y") {
				select {
				case approvalCh <- struct{}{}:
				default:
				}
			}
			if err != nil || n == 0 {
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
}

// waitFifoApproval drains any stale presses, then waits for a fresh "y" or the
// timeout. A timeout of 0 waits indefinitely.
func waitFifoApproval(ctx context.Context, description string, timeout time.Duration) bool {
	for {
		select {
		case <-approvalCh:
			continue
		default:
		}
		break
	}
	fmt.Printf("\n>>> %s\n>>> write \"y\" to the approval FIFO within %s ...\n", description, timeout)
	var timer <-chan time.Time
	if timeout > 0 {
		timer = time.After(timeout)
	}
	select {
	case <-approvalCh:
		fmt.Println(">>> APPROVED")
		return true
	case <-timer:
		fmt.Println(">>> DENIED (timeout, no approval)")
		return false
	case <-ctx.Done():
		fmt.Println(">>> CANCELLED by the host")
		return false
	}
}
