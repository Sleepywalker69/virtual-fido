//go:build windows

package main

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/bulwarkid/virtual-fido/desktop"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
)

var errorColor = walk.RGB(0xB9, 0x1C, 0x1C)
var mutedColor = walk.RGB(0x4B, 0x55, 0x63)

// runUnlockDialog asks for the vault passphrase (or creates a new vault on
// first run). It returns false if the user quits.
func (a *app) runUnlockDialog() bool {
	creating := !a.service.VaultExists()
	var dlg *walk.Dialog
	var passphrase, confirm *walk.LineEdit
	var remember *walk.CheckBox
	var message *walk.Label
	var okButton, quitButton *walk.PushButton

	intro := "Enter the passphrase that protects your passkeys."
	okText := "Unlock"
	if creating {
		intro = fmt.Sprintf("Welcome! Choose a passphrase (at least %d characters) to encrypt your passkeys.\n"+
			"They are stored in %s.\nIf you forget the passphrase, the passkeys cannot be recovered.",
			desktop.MinPassphraseLength, a.settings.VaultPath)
		okText = "Create vault"
	}

	submit := func() {
		var err error
		switch {
		case creating && passphrase.Text() != confirm.Text():
			err = errors.New("the passphrases do not match")
		case creating:
			err = a.service.CreateVault(passphrase.Text())
		default:
			err = a.service.Unlock(passphrase.Text())
		}
		if err != nil {
			message.SetText(err.Error())
			passphrase.SetFocus()
			return
		}
		a.rememberPassphrase(remember.Checked(), passphrase.Text())
		dlg.Accept()
	}

	children := []Widget{
		Label{Text: intro},
		Label{Text: "Passphrase:"},
		LineEdit{AssignTo: &passphrase, PasswordMode: true},
	}
	if creating {
		children = append(children,
			Label{Text: "Repeat the passphrase:"},
			LineEdit{AssignTo: &confirm, PasswordMode: true},
		)
	}
	children = append(children,
		CheckBox{Alignment: AlignHNearVCenter, AssignTo: &remember, Text: "Unlock automatically on this PC (protected by your Windows account)",
			Checked: len(a.settings.ProtectedPassphrase) > 0},
		Label{AssignTo: &message, TextColor: errorColor},
		Composite{
			Layout: HBox{MarginsZero: true},
			Children: []Widget{
				HSpacer{},
				PushButton{AssignTo: &okButton, Text: okText, OnClicked: submit},
				PushButton{AssignTo: &quitButton, Text: "Quit", OnClicked: func() { dlg.Cancel() }},
			},
		},
	)
	result, err := Dialog{
		AssignTo:      &dlg,
		Title:         "Virtual FIDO",
		Icon:          a.icons.normal,
		DefaultButton: &okButton,
		CancelButton:  &quitButton,
		MinSize:       Size{Width: 460},
		Layout:        VBox{Margins: Margins{Left: 16, Top: 14, Right: 16, Bottom: 12}},
		Children:      children,
	}.Run(nil)
	if err != nil {
		walk.MsgBox(nil, "Virtual FIDO", "Could not open the unlock window: "+err.Error(), walk.MsgBoxIconError)
		return false
	}
	return result == walk.DlgCmdOK
}

// rememberPassphrase stores (or forgets) the passphrase, encrypted for the
// current Windows account.
func (a *app) rememberPassphrase(remember bool, passphrase string) {
	if remember {
		protected, err := desktop.ProtectPassphrase(passphrase)
		if err != nil {
			a.service.Log.Printf("Could not remember the passphrase: %v", err)
			return
		}
		a.settings.ProtectedPassphrase = protected
	} else {
		a.settings.ProtectedPassphrase = nil
	}
	a.saveSettings()
}

// runPINDialog sets or changes the PIN.
func (a *app) runPINDialog() {
	var dlg *walk.Dialog
	var pin, confirm *walk.LineEdit
	var message *walk.Label
	var okButton, cancelButton *walk.PushButton
	Dialog{
		AssignTo:      &dlg,
		Title:         "Set PIN",
		Icon:          a.icons.normal,
		DefaultButton: &okButton,
		CancelButton:  &cancelButton,
		MinSize:       Size{Width: 380},
		Layout:        VBox{Margins: Margins{Left: 16, Top: 14, Right: 16, Bottom: 12}},
		Children: []Widget{
			Label{Text: "Windows asks for this PIN when a website wants to verify it's you.\nUse at least 4 characters."},
			Label{Text: "New PIN:"},
			LineEdit{AssignTo: &pin, PasswordMode: true},
			Label{Text: "Repeat the PIN:"},
			LineEdit{AssignTo: &confirm, PasswordMode: true},
			Label{AssignTo: &message, TextColor: errorColor},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					HSpacer{},
					PushButton{AssignTo: &okButton, Text: "Set PIN", OnClicked: func() {
						if pin.Text() != confirm.Text() {
							message.SetText("The PINs do not match.")
							return
						}
						if err := a.service.SetPIN(pin.Text()); err != nil {
							message.SetText(err.Error())
							return
						}
						dlg.Accept()
					}},
					PushButton{AssignTo: &cancelButton, Text: "Cancel", OnClicked: func() { dlg.Cancel() }},
				},
			},
		},
	}.Run(a.mw)
}

// runPassphraseDialog changes the vault passphrase.
func (a *app) runPassphraseDialog() {
	var dlg *walk.Dialog
	var current, next, confirm *walk.LineEdit
	var message *walk.Label
	var okButton, cancelButton *walk.PushButton
	Dialog{
		AssignTo:      &dlg,
		Title:         "Change vault passphrase",
		Icon:          a.icons.normal,
		DefaultButton: &okButton,
		CancelButton:  &cancelButton,
		MinSize:       Size{Width: 400},
		Layout:        VBox{Margins: Margins{Left: 16, Top: 14, Right: 16, Bottom: 12}},
		Children: []Widget{
			Label{Text: "Current passphrase:"},
			LineEdit{AssignTo: &current, PasswordMode: true},
			Label{Text: fmt.Sprintf("New passphrase (at least %d characters):", desktop.MinPassphraseLength)},
			LineEdit{AssignTo: &next, PasswordMode: true},
			Label{Text: "Repeat the new passphrase:"},
			LineEdit{AssignTo: &confirm, PasswordMode: true},
			Label{AssignTo: &message, TextColor: errorColor},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					HSpacer{},
					PushButton{AssignTo: &okButton, Text: "Change", OnClicked: func() {
						if next.Text() != confirm.Text() {
							message.SetText("The new passphrases do not match.")
							return
						}
						if err := a.service.ChangePassphrase(current.Text(), next.Text()); err != nil {
							message.SetText(err.Error())
							return
						}
						if len(a.settings.ProtectedPassphrase) > 0 {
							a.rememberPassphrase(true, next.Text())
						}
						dlg.Accept()
					}},
					PushButton{AssignTo: &cancelButton, Text: "Cancel", OnClicked: func() { dlg.Cancel() }},
				},
			},
		},
	}.Run(a.mw)
}

// approvalWindow is the pop-up for one pending approval request.
type approvalWindow struct {
	request   *desktop.ApprovalRequest
	dialog    *walk.Dialog
	countdown *walk.Label
	stop      chan struct{}
}

// showApproval opens the approval pop-up on top of everything else (the
// browser's security key dialog is usually in front).
func (a *app) showApproval(request *desktop.ApprovalRequest) {
	select {
	case <-request.Done():
		return // already resolved (e.g. cancelled by the browser)
	default:
	}
	a.closeApprovalWindow()

	hint := "Click Approve to continue, or Deny."
	if a.settings.ApproveHotkey != "" {
		hint = fmt.Sprintf("Press %s (your macropad key) or click Approve.", a.settings.ApproveHotkey)
	}
	var dialog *walk.Dialog
	var approveButton, denyButton *walk.PushButton
	var countdown *walk.Label
	err := Dialog{
		AssignTo:     &dialog,
		Title:        approvalWindowTitle,
		Icon:         a.icons.attention,
		CancelButton: &denyButton, // Esc denies; Enter does nothing, so nothing is approved by accident
		MinSize:      Size{Width: 440},
		Layout:       VBox{Margins: Margins{Left: 20, Top: 16, Right: 20, Bottom: 14}, Spacing: 6},
		Children: []Widget{
			Label{Text: request.Title(), Font: Font{PointSize: 14, Bold: true}},
			Label{Text: request.Detail(), Visible: request.Detail() != ""},
			Label{Text: hint},
			Label{AssignTo: &countdown, TextColor: mutedColor},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					HSpacer{},
					PushButton{AssignTo: &approveButton, Text: "&Approve", MinSize: Size{Width: 110}, OnClicked: request.Approve},
					PushButton{AssignTo: &denyButton, Text: "&Deny", MinSize: Size{Width: 90}, OnClicked: request.Deny},
				},
			},
		},
	}.Create(nil)
	if err != nil {
		a.service.Log.Printf("Could not show the approval window: %v", err)
		return
	}
	// Closing the window without choosing denies the request.
	dialog.Closing().Attach(func(canceled *bool, reason walk.CloseReason) { request.Deny() })
	window := &approvalWindow{request: request, dialog: dialog, countdown: countdown, stop: make(chan struct{})}
	a.approval = window
	a.updateCountdown(window)

	dialog.Show()
	centerOnWorkArea(dialog)
	setTopmost(dialog.Handle())
	forceForeground(dialog.Handle())
	// Start on Deny: a stray key press while the pop-up steals focus must
	// never approve anything.
	denyButton.SetFocus()
	flashWindow(dialog.Handle())
	win.MessageBeep(win.MB_ICONASTERISK)
	a.tray.SetIcon(a.icons.attention)
	a.refreshStatus()

	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-window.stop:
				return
			case <-ticker.C:
				a.mw.Synchronize(func() { a.updateCountdown(window) })
			}
		}
	}()
}

func (a *app) updateCountdown(window *approvalWindow) {
	if a.approval != window {
		return
	}
	deadline := window.request.Deadline
	if deadline.IsZero() {
		window.countdown.SetText("")
		return
	}
	remaining := time.Until(deadline).Round(time.Second)
	if remaining < 0 {
		remaining = 0
	}
	window.countdown.SetText(fmt.Sprintf("Denied automatically in %d s.", int(remaining.Seconds())))
}

// closeApproval closes the pop-up for a request once it is resolved.
func (a *app) closeApproval(request *desktop.ApprovalRequest) {
	if a.approval == nil || a.approval.request != request {
		return
	}
	a.closeApprovalWindow()
	a.service.Log.Printf("%s: %s", request.Title(), request.Outcome())
	if request.Outcome() == desktop.ApprovalTimedOut {
		a.notify("Request denied", request.Title()+": nobody answered in time.")
	}
	a.refreshStatus()
}

func (a *app) closeApprovalWindow() {
	window := a.approval
	if window == nil {
		return
	}
	a.approval = nil
	close(window.stop)
	window.dialog.Close(walk.DlgCmdCancel)
}

// centerOnWorkArea centres a window on the primary monitor's work area.
func centerOnWorkArea(dialog *walk.Dialog) {
	var info win.MONITORINFO
	info.CbSize = uint32(unsafe.Sizeof(info))
	monitor := win.MonitorFromWindow(dialog.Handle(), win.MONITOR_DEFAULTTOPRIMARY)
	if !win.GetMonitorInfo(monitor, &info) {
		return
	}
	work := info.RcWork
	bounds := dialog.BoundsPixels()
	bounds.X = int(work.Left) + (int(work.Right-work.Left)-bounds.Width)/2
	bounds.Y = int(work.Top) + (int(work.Bottom-work.Top)-bounds.Height)/3
	dialog.SetBoundsPixels(bounds)
}
