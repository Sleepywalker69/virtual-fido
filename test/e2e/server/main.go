// Command server runs the desktop authenticator core headless for the
// end-to-end tests (test/e2e/e2e_usbip_fido2.py). Approvals follow a policy
// file instead of a person: "approve", "deny" or "delay <ms> approve|deny".
// FOR TESTING ONLY: it approves requests without asking anyone.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/bulwarkid/virtual-fido/desktop"
)

func main() {
	vault := flag.String("vault", "e2e-vault.json", "vault file (created if missing)")
	passphrase := flag.String("passphrase", "e2e test passphrase", "vault passphrase")
	policyFile := flag.String("policy-file", "", "approval policy file")
	address := flag.String("listen", "127.0.0.1:3240", "USB/IP listen address")
	noPIN := flag.Bool("no-pin", false, "disable PIN support")
	verbose := flag.Bool("v", false, "trace logging")
	flag.Parse()

	settings := desktop.DefaultSettings(".")
	settings.VaultPath = *vault
	service := desktop.NewService(settings, nil)
	service.ListenAddress = *address
	service.SetVerboseLogging(*verbose)
	service.Approvals.Timeout = 20 * time.Second
	service.Approvals.OnRequest = func(request *desktop.ApprovalRequest) {
		go applyPolicy(request, *policyFile)
	}
	service.Approvals.OnResolved = func(request *desktop.ApprovalRequest) {
		fmt.Printf("approval %d %q: %s\n", request.ID, request.Title(), request.Outcome())
	}
	service.Log.SetTee(os.Stdout)

	var err error
	if service.VaultExists() {
		err = service.Unlock(*passphrase)
	} else {
		err = service.CreateVault(*passphrase)
	}
	if err == nil && *noPIN {
		err = service.SetPINSupport(false)
	}
	if err == nil {
		err = service.Start()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Println("e2e server ready")
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	<-signals
	service.Stop()
}

func applyPolicy(request *desktop.ApprovalRequest, policyFile string) {
	policy := "approve"
	if policyFile != "" {
		if data, err := os.ReadFile(policyFile); err == nil {
			policy = strings.TrimSpace(string(data))
		}
	}
	fields := strings.Fields(policy)
	approve := len(fields) > 0 && fields[len(fields)-1] == "approve"
	if len(fields) >= 2 && fields[0] == "delay" {
		ms, _ := strconv.Atoi(fields[1])
		select {
		case <-time.After(time.Duration(ms) * time.Millisecond):
		case <-request.Done():
			return
		}
	}
	if approve {
		request.Approve()
	} else {
		request.Deny()
	}
}
