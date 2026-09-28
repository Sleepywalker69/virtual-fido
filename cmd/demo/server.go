package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	virtual_fido "github.com/bulwarkid/virtual-fido"
	"github.com/bulwarkid/virtual-fido/fido_client"
)

var stdinLines = make(chan string)
var stdinOnce sync.Once

// readStdin feeds terminal lines to prompt; reading happens in the background
// so a prompt can be abandoned when the host cancels the request.
func readStdin() {
	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			close(stdinLines)
			return
		}
		stdinLines <- line
	}
}

func prompt(ctx context.Context, prompt string) bool {
	stdinOnce.Do(func() { go readStdin() })
	// Discard anything typed before this prompt appeared.
	for drained := false; !drained; {
		select {
		case <-stdinLines:
		default:
			drained = true
		}
	}
	fmt.Println(prompt)
	fmt.Print("--> ")
	select {
	case response, ok := <-stdinLines:
		if !ok {
			fmt.Println("Could not read user input; denying")
			return false
		}
		response = strings.ToLower(strings.TrimSpace(response))
		return response == "y" || response == "yes"
	case <-ctx.Done():
		fmt.Println("\n>>> CANCELLED by the host")
		return false
	}
}

type ClientSupport struct {
	vaultFilename   string
	vaultPassphrase string
	fingerprintUser string
	fpUserOnce      sync.Once
}

func (support *ClientSupport) ApproveClientAction(action fido_client.ClientAction, params fido_client.ClientActionRequestParams) bool {
	return support.ApproveClientActionContext(context.Background(), action, params)
}

func (support *ClientSupport) ApproveClientActionContext(ctx context.Context, action fido_client.ClientAction, params fido_client.ClientActionRequestParams) bool {
	site := params.RelyingPartyID
	if site == "" {
		site = params.RelyingParty
	}
	var description string
	switch action {
	case fido_client.ClientActionFIDOGetAssertion:
		description = fmt.Sprintf("login to \"%s\" as \"%s\"", site, params.UserName)
	case fido_client.ClientActionFIDOMakeCredential:
		description = fmt.Sprintf("account creation for \"%s\"", site)
	case fido_client.ClientActionU2FAuthenticate:
		description = "U2F authentication (login)"
	case fido_client.ClientActionU2FRegister:
		description = "U2F registration (enroll)"
	default:
		fmt.Printf("Unknown client action for approval: %d\n", action)
		return false
	}
	return approveAction(ctx, description)
}

// SaveData replaces the vault atomically (write a temporary file, then rename)
// so a crash mid-write cannot destroy the stored credentials.
func (support *ClientSupport) SaveData(data []byte) {
	dir := filepath.Dir(support.vaultFilename)
	f, err := os.CreateTemp(dir, filepath.Base(support.vaultFilename)+".tmp-*")
	checkErr(err, "Could not create temporary vault file")
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(f.Name(), 0600)
	}
	if err == nil {
		err = os.Rename(f.Name(), support.vaultFilename)
	}
	if err != nil {
		os.Remove(f.Name())
	}
	checkErr(err, "Could not write vault data")
}

func (support *ClientSupport) RetrieveData() []byte {
	f, err := os.Open(support.vaultFilename)
	if os.IsNotExist(err) {
		return nil
	}
	checkErr(err, "Could not open vault")
	defer f.Close()
	data, err := io.ReadAll(f)
	checkErr(err, "Could not read vault data")
	return data
}

func (support *ClientSupport) Passphrase() string {
	return support.vaultPassphrase
}

func (support *ClientSupport) SupportsUserVerification() bool {
	return support.platformSupportsUserVerification()
}

func (support *ClientSupport) VerifyUser(action fido_client.ClientAction, params fido_client.ClientActionRequestParams) bool {
	return support.platformVerifyUser(action, params)
}

func (support *ClientSupport) resolveFingerprintUser() string {
	support.fpUserOnce.Do(func() {
		if support.fingerprintUser != "" {
			return
		}
		for _, key := range []string{"FPRINTD_USER", "SUDO_USER", "USER", "LOGNAME", "USERNAME"} {
			if val := os.Getenv(key); val != "" {
				support.fingerprintUser = val
				return
			}
		}
		if current, err := user.Current(); err == nil && current != nil && current.Username != "" {
			support.fingerprintUser = current.Username
		}
	})
	return support.fingerprintUser
}

func (support *ClientSupport) fingerprintPrompt(action fido_client.ClientAction, params fido_client.ClientActionRequestParams) string {
	switch action {
	case fido_client.ClientActionFIDOMakeCredential:
		if params.RelyingParty != "" {
			return fmt.Sprintf("Scan your finger to create a credential for \"%s\".", params.RelyingParty)
		}
		return "Scan your finger to create a new credential."
	case fido_client.ClientActionFIDOGetAssertion:
		target := params.RelyingParty
		if target == "" {
			target = "this request"
		}
		if params.UserName != "" {
			return fmt.Sprintf("Scan your finger to approve %s as %s.", target, params.UserName)
		}
		return fmt.Sprintf("Scan your finger to approve %s.", target)
	case fido_client.ClientActionU2FAuthenticate, fido_client.ClientActionU2FRegister:
		return "Scan your finger to authorize the U2F action."
	case fido_client.ClientActionManageAuthenticator:
		return "Scan your finger to enable fingerprint verification."
	default:
		return "Scan your finger to continue."
	}
}

func runServer(client virtual_fido.FIDOClient) {
	startApprovalListener()
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		virtual_fido.Start(client)
		wg.Done()
	}()
	go func() {
		time.Sleep(500 * time.Millisecond)
		prog := platformUSBIPExec()
		if prog != nil {
			prog.Stdin = os.Stdin
			prog.Stdout = os.Stdout
			prog.Stderr = os.Stderr
			err := prog.Run()
			if err != nil {
				fmt.Printf("Error: %s\n", err)
			}
		}
		wg.Done()
	}()
	wg.Wait()
}
