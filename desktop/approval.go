package desktop

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bulwarkid/virtual-fido/fido_client"
)

// ApprovalOutcome is how an approval request ended.
type ApprovalOutcome int

const (
	ApprovalPending ApprovalOutcome = iota
	ApprovalApproved
	ApprovalDenied
	ApprovalTimedOut
	// ApprovalCancelled means the browser or OS withdrew the request (or the
	// device was detached) before the user decided.
	ApprovalCancelled
)

func (o ApprovalOutcome) String() string {
	switch o {
	case ApprovalApproved:
		return "approved"
	case ApprovalDenied:
		return "denied"
	case ApprovalTimedOut:
		return "timed out"
	case ApprovalCancelled:
		return "cancelled by the browser"
	}
	return "pending"
}

// ApprovalRequest is one "a website wants to use your authenticator" prompt.
type ApprovalRequest struct {
	ID       uint64
	Action   fido_client.ClientAction
	Params   fido_client.ClientActionRequestParams
	Created  time.Time
	Deadline time.Time

	decision chan bool
	done     chan struct{}
	mu       sync.Mutex
	outcome  ApprovalOutcome
}

// Approve resolves the request as approved (the first decision wins).
func (r *ApprovalRequest) Approve() { r.decide(true) }

// Deny resolves the request as denied (the first decision wins).
func (r *ApprovalRequest) Deny() { r.decide(false) }

func (r *ApprovalRequest) decide(approved bool) {
	select {
	case r.decision <- approved:
	default:
	}
}

// Done is closed once the request is resolved for any reason.
func (r *ApprovalRequest) Done() <-chan struct{} { return r.done }

// Outcome reports how the request ended (ApprovalPending until Done closes).
func (r *ApprovalRequest) Outcome() ApprovalOutcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.outcome
}

// Site is the domain the request is for (vouched for by the browser), or ""
// for legacy U2F requests, which only carry a hash of it.
func (r *ApprovalRequest) Site() string {
	if r.Params.RelyingPartyID != "" {
		return r.Params.RelyingPartyID
	}
	return r.Params.RelyingParty
}

// Title is a one-line summary for the prompt.
func (r *ApprovalRequest) Title() string {
	site := r.Site()
	switch r.Action {
	case fido_client.ClientActionFIDOMakeCredential:
		if site != "" {
			return fmt.Sprintf("Create a passkey for %s", site)
		}
		return "Create a passkey"
	case fido_client.ClientActionFIDOGetAssertion:
		if site != "" {
			return fmt.Sprintf("Sign in to %s", site)
		}
		return "Sign in"
	case fido_client.ClientActionU2FRegister:
		return "Register this security key (U2F)"
	case fido_client.ClientActionU2FAuthenticate:
		return "Use this security key (U2F)"
	}
	return "Allow this request"
}

// Detail describes the account and the site's own name, if any.
func (r *ApprovalRequest) Detail() string {
	detail := ""
	if r.Params.UserName != "" {
		detail = "Account: " + r.Params.UserName
	}
	if name := r.Params.RelyingParty; name != "" && name != r.Params.RelyingPartyID {
		if detail != "" {
			detail += "\n"
		}
		detail += fmt.Sprintf("The site calls itself %q", name)
	}
	return detail
}

func (r *ApprovalRequest) finish(outcome ApprovalOutcome) {
	r.mu.Lock()
	r.outcome = outcome
	r.mu.Unlock()
	close(r.done)
}

// ApprovalBroker turns authenticator approval calls into ApprovalRequests for
// the UI (and hotkeys) to resolve. Only one request is pending at a time,
// because the authenticator handles one command at a time.
type ApprovalBroker struct {
	// Timeout denies a request nobody answers. Zero means wait until the
	// browser gives up. Change it with SetTimeout once requests may arrive.
	Timeout time.Duration
	// OnRequest is called (from an authenticator goroutine) when a request
	// needs the user; it must not block.
	OnRequest func(*ApprovalRequest)
	// OnResolved is called once the request is resolved; it must not block.
	OnResolved func(*ApprovalRequest)

	mu      sync.Mutex
	current *ApprovalRequest
	nextID  uint64
}

// SetTimeout changes Timeout safely while requests may be in flight.
func (b *ApprovalBroker) SetTimeout(timeout time.Duration) {
	b.mu.Lock()
	b.Timeout = timeout
	b.mu.Unlock()
}

// ApproveClientAction implements fido_client.ClientRequestApprover.
func (b *ApprovalBroker) ApproveClientAction(action fido_client.ClientAction, params fido_client.ClientActionRequestParams) bool {
	return b.ApproveClientActionContext(context.Background(), action, params)
}

// ApproveClientActionContext implements fido_client.ContextRequestApprover:
// it waits for a decision, the timeout, or ctx (the browser cancelling).
func (b *ApprovalBroker) ApproveClientActionContext(ctx context.Context, action fido_client.ClientAction, params fido_client.ClientActionRequestParams) bool {
	b.mu.Lock()
	b.nextID++
	now := time.Now()
	timeoutDuration := b.Timeout
	request := &ApprovalRequest{
		ID:       b.nextID,
		Action:   action,
		Params:   params,
		Created:  now,
		decision: make(chan bool, 1),
		done:     make(chan struct{}),
	}
	if timeoutDuration > 0 {
		request.Deadline = now.Add(timeoutDuration)
	}
	b.current = request
	onRequest, onResolved := b.OnRequest, b.OnResolved
	b.mu.Unlock()

	if onRequest != nil {
		onRequest(request)
	}
	var timeout <-chan time.Time
	if timeoutDuration > 0 {
		timer := time.NewTimer(timeoutDuration)
		defer timer.Stop()
		timeout = timer.C
	}
	outcome := ApprovalDenied
	select {
	case approved := <-request.decision:
		if approved {
			outcome = ApprovalApproved
		}
	case <-timeout:
		outcome = ApprovalTimedOut
	case <-ctx.Done():
		outcome = ApprovalCancelled
	}
	request.finish(outcome)
	b.mu.Lock()
	if b.current == request {
		b.current = nil
	}
	b.mu.Unlock()
	if onResolved != nil {
		onResolved(request)
	}
	return outcome == ApprovalApproved
}

// Current returns the pending request, if any.
func (b *ApprovalBroker) Current() *ApprovalRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.current
}

// ApproveCurrent approves the pending request (e.g. from a hotkey); it
// reports whether there was one.
func (b *ApprovalBroker) ApproveCurrent() bool {
	if request := b.Current(); request != nil {
		request.Approve()
		return true
	}
	return false
}

// DenyCurrent denies the pending request; it reports whether there was one.
func (b *ApprovalBroker) DenyCurrent() bool {
	if request := b.Current(); request != nil {
		request.Deny()
		return true
	}
	return false
}
