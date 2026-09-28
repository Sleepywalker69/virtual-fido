//go:build windows

// Command vfido-gui is the Windows app for Virtual FIDO: a virtual FIDO2
// security key with a window, approval pop-ups, a notification-area icon and a
// global hotkey (for a macropad) to approve requests.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"image/color"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bulwarkid/virtual-fido/cmd/vfido-gui/appicon"
	"github.com/bulwarkid/virtual-fido/desktop"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
)

const (
	mainWindowTitle     = "Virtual FIDO"
	approvalWindowTitle = "Virtual FIDO - approve?"
)

var (
	colorGreen = walk.RGB(0x15, 0x80, 0x3D)
	colorRed   = walk.RGB(0xB9, 0x1C, 0x1C)
)

type icons struct {
	normal, attention, stopped *walk.Icon
}

type app struct {
	settings *desktop.Settings
	service  *desktop.Service
	hotkeys  *hotkeyManager
	icons    icons
	verbose  bool
	exiting  bool
	shown    *walk.Icon // icon currently on the window
	// approveHotkeyActive is the approve hotkey as registered ("" if none
	// or registration failed), for the pop-up hint.
	approveHotkeyActive string

	mw       *walk.MainWindow
	tray     *walk.NotifyIcon
	approval *approvalWindow

	statusImage                             *walk.ImageView
	statusText, statusDetail                *walk.Label
	driverButton, attachButton, startButton *walk.PushButton

	credentialTable *walk.TableView
	credentialModel *credentialModel
	deleteButton    *walk.PushButton

	pinStatus                    *walk.Label
	pinSupport                   *walk.CheckBox
	setPINButton, clearPINButton *walk.PushButton

	approveHotkey, denyHotkey *walk.ComboBox
	timeoutEdit               *walk.NumberEdit
	hotkeyStatus              *walk.Label

	rememberCheck, autoAttachCheck, minimizedCheck, signInCheck *walk.CheckBox

	logView    *walk.TextEdit
	logVersion uint64
}

func main() {
	runtime.LockOSThread()
	minimized := flag.Bool("minimized", false, "start in the notification area")
	verbose := flag.Bool("verbose", false, "log every USB/CTAP message")
	flag.Parse()

	if !acquireSingleInstance() {
		showExistingInstance()
		return
	}
	dir, err := desktop.DefaultSettingsDir()
	if err != nil {
		walk.MsgBox(nil, mainWindowTitle, "Cannot find the settings folder: "+err.Error(), walk.MsgBoxIconError)
		return
	}
	settings, err := desktop.LoadSettings(dir)
	if err != nil {
		walk.MsgBox(nil, mainWindowTitle, "Your settings could not be read and were reset: "+err.Error(), walk.MsgBoxIconWarning)
	}
	a := &app{settings: settings, verbose: *verbose}
	a.run(*minimized || settings.StartMinimized)
}

func (a *app) run(startHidden bool) {
	a.service = desktop.NewService(a.settings, desktop.NewUsbipAttacher(func() string { return a.settings.UsbipPath }))
	a.service.SetVerboseLogging(a.verbose)
	a.loadIcons()
	if err := a.createMainWindow(); err != nil {
		walk.MsgBox(nil, mainWindowTitle, "Could not create the window: "+err.Error(), walk.MsgBoxIconError)
		return
	}
	defer a.shutdown()
	if err := a.createTray(); err != nil {
		a.service.Log.Printf("Notification area icon unavailable: %v", err)
	}
	a.hotkeys = startHotkeyManager(func(id int) {
		// WM_HOTKEY arrives on the hotkey thread; resolving is thread-safe.
		switch id {
		case hotkeyApprove:
			a.service.Approvals.ApproveCurrent()
		case hotkeyDeny:
			a.service.Approvals.DenyCurrent()
		}
	})
	a.service.OnChange = func() { a.mw.Synchronize(a.refreshStatus) }
	a.service.Approvals.OnRequest = func(request *desktop.ApprovalRequest) {
		a.mw.Synchronize(func() { a.showApproval(request) })
	}
	a.service.Approvals.OnResolved = func(request *desktop.ApprovalRequest) {
		a.mw.Synchronize(func() { a.closeApproval(request) })
	}

	if !a.unlock() {
		return
	}
	a.applyHotkeys()
	a.loadSettingsIntoUI()
	a.refreshCredentials()
	a.startAuthenticator()
	if !startHidden {
		a.showMainWindow()
	} else {
		a.notify("Virtual FIDO is running", "Your virtual security key is available. Click this icon to open Virtual FIDO.")
	}
	go a.pollLoop()
	a.mw.Run()
}

// loadIcons loads the icons embedded by go-winres (sharp at every DPI),
// falling back to drawing them if the build has no resources.
func (a *app) loadIcons() {
	load := func(name string, background color.RGBA) *walk.Icon {
		if icon, err := walk.NewIconFromResource(name); err == nil {
			return icon
		}
		icon, _ := walk.NewIconFromImageForDPI(appicon.Draw(32, background), 96)
		return icon
	}
	a.icons.normal = load("APP", appicon.Blue)
	a.icons.attention = load("ATTENTION", appicon.Amber)
	a.icons.stopped = load("STOPPED", appicon.Gray)
}

// unlock uses the remembered passphrase if there is one, otherwise asks.
func (a *app) unlock() bool {
	if len(a.settings.ProtectedPassphrase) > 0 && a.service.VaultExists() {
		if passphrase, err := desktop.UnprotectPassphrase(a.settings.ProtectedPassphrase); err == nil {
			if a.service.Unlock(passphrase) == nil {
				return true
			}
		}
		a.service.Log.Printf("The remembered passphrase did not work; asking instead")
	}
	return a.runUnlockDialog()
}

func (a *app) createMainWindow() error {
	a.credentialModel = &credentialModel{}
	hotkeyChoices := append([]string{"(none)"}, desktop.SuggestedHotkeys[1:]...)
	return MainWindow{
		AssignTo: &a.mw,
		Title:    mainWindowTitle,
		Icon:     a.icons.normal,
		Size:     Size{Width: 760, Height: 540},
		MinSize:  Size{Width: 600, Height: 440},
		Visible:  false,
		Layout:   VBox{Margins: Margins{Left: 12, Top: 10, Right: 12, Bottom: 10}},
		Children: []Widget{
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					ImageView{AssignTo: &a.statusImage, Image: a.icons.stopped, Mode: ImageViewModeIdeal},
					Composite{
						StretchFactor: 1,
						Layout:        VBox{MarginsZero: true, SpacingZero: true},
						Children: []Widget{
							Label{AssignTo: &a.statusText, Font: Font{PointSize: 11, Bold: true}},
							Label{AssignTo: &a.statusDetail, TextColor: mutedColor},
						},
					},
					PushButton{
						AssignTo:  &a.driverButton,
						Text:      "Get the USB/IP driver…",
						Visible:   false,
						OnClicked: func() { openURL(desktop.UsbipWin2DownloadURL) },
					},
					PushButton{AssignTo: &a.attachButton, Text: "Attach", OnClicked: a.onAttach},
					PushButton{AssignTo: &a.startButton, Text: "Stop", OnClicked: a.onStartStop},
				},
			},
			TabWidget{
				Pages: []TabPage{
					{
						Title:  "Passkeys",
						Layout: VBox{},
						Children: []Widget{
							TableView{
								AssignTo:              &a.credentialTable,
								AlternatingRowBG:      true,
								Model:                 a.credentialModel,
								OnCurrentIndexChanged: a.updateCredentialButtons,
								Columns: []TableViewColumn{
									{Title: "Website", Width: 220},
									{Title: "Account", Width: 220},
									{Title: "Type", Width: 120},
									{Title: "Sign-ins", Width: 70, Alignment: AlignFar},
								},
							},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									Label{Text: "Passkeys are created when a website asks for a security key and you approve.", TextColor: mutedColor},
									HSpacer{},
									PushButton{AssignTo: &a.deleteButton, Text: "Delete…", Enabled: false, OnClicked: a.onDeleteCredential},
								},
							},
						},
					},
					{
						Title:  "PIN",
						Layout: VBox{},
						Children: []Widget{
							Label{Text: "A PIN protects your passkeys: Windows asks for it when a website wants to verify it's really you.\n" +
								"If you have no PIN yet, Windows offers to create one the first time a site needs it."},
							Label{AssignTo: &a.pinStatus, Font: Font{Bold: true}},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									PushButton{AssignTo: &a.setPINButton, Text: "Set PIN…", OnClicked: a.runPINDialog},
									PushButton{AssignTo: &a.clearPINButton, Text: "Remove PIN", OnClicked: a.onClearPIN},
									HSpacer{},
								},
							},
							CheckBox{Alignment: AlignHNearVCenter, AssignTo: &a.pinSupport, Text: "Offer PIN protection to Windows (recommended)", OnClicked: a.onPINSupport},
							VSpacer{},
						},
					},
					{
						Title:  "Approval",
						Layout: VBox{},
						Children: []Widget{
							Label{Text: "Virtual FIDO asks you before any website creates or uses a passkey.\n" +
								"Approve in the pop-up, or press a hotkey: program a macropad key to send it (F13–F24 are ideal, no keyboard has them)."},
							Composite{
								Layout: Grid{Columns: 2, MarginsZero: true},
								Children: []Widget{
									Label{Text: "Approve hotkey:"},
									ComboBox{AssignTo: &a.approveHotkey, Editable: true, Model: hotkeyChoices},
									Label{Text: "Deny hotkey:"},
									ComboBox{AssignTo: &a.denyHotkey, Editable: true, Model: hotkeyChoices},
									Label{Text: "Deny automatically after:"},
									NumberEdit{AssignTo: &a.timeoutEdit, MinValue: 0, MaxValue: 600, Decimals: 0, Suffix: " seconds (0 = never)"},
								},
							},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									PushButton{Text: "Apply", OnClicked: a.onApplyApprovalSettings},
									Label{AssignTo: &a.hotkeyStatus},
									HSpacer{},
								},
							},
							VSpacer{},
						},
					},
					{
						Title:  "Settings",
						Layout: VBox{},
						Children: []Widget{
							CheckBox{Alignment: AlignHNearVCenter, AssignTo: &a.rememberCheck, Text: "Unlock automatically on this PC (passphrase protected by your Windows account)", OnClicked: a.onRememberToggled},
							CheckBox{Alignment: AlignHNearVCenter, AssignTo: &a.autoAttachCheck, Text: "Attach the security key to Windows when Virtual FIDO starts", OnClicked: a.onGeneralSetting},
							CheckBox{Alignment: AlignHNearVCenter, AssignTo: &a.minimizedCheck, Text: "Start in the notification area", OnClicked: a.onGeneralSetting},
							CheckBox{Alignment: AlignHNearVCenter, AssignTo: &a.signInCheck, Text: "Start Virtual FIDO when I sign in to Windows", OnClicked: a.onSignInToggled},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									PushButton{Text: "Change vault passphrase…", OnClicked: a.runPassphraseDialog},
									PushButton{Text: "Open data folder", OnClicked: func() { openURL(filepath.Dir(a.settings.VaultPath)) }},
									HSpacer{},
								},
							},
							Label{Text: "Vault: " + a.settings.VaultPath, TextColor: mutedColor},
							VSpacer{},
						},
					},
					{
						Title:  "Log",
						Layout: VBox{},
						Children: []Widget{
							TextEdit{AssignTo: &a.logView, ReadOnly: true, VScroll: true, Font: Font{Family: "Consolas", PointSize: 9}},
							Composite{
								Layout: HBox{MarginsZero: true},
								Children: []Widget{
									HSpacer{},
									PushButton{Text: "Copy log", OnClicked: func() {
										lines, _ := a.service.Log.Snapshot()
										walk.Clipboard().SetText(strings.Join(lines, "\r\n"))
									}},
								},
							},
						},
					},
				},
			},
		},
	}.Create()
}

func (a *app) createTray() error {
	tray, err := walk.NewNotifyIcon(a.mw)
	if err != nil {
		return err
	}
	a.tray = tray
	tray.SetIcon(a.icons.normal)
	tray.SetToolTip(mainWindowTitle)
	tray.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			a.showMainWindow()
		}
	})
	addAction := func(text string, handler func()) {
		action := walk.NewAction()
		action.SetText(text)
		action.Triggered().Attach(handler)
		tray.ContextMenu().Actions().Add(action)
	}
	addAction("&Open Virtual FIDO", a.showMainWindow)
	addAction("&Attach to Windows", a.onAttach)
	tray.ContextMenu().Actions().Add(walk.NewSeparatorAction())
	addAction("E&xit", a.exit)
	a.mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		if !a.exiting {
			// Closing the window keeps the security key running.
			*canceled = true
			a.mw.Hide()
		}
	})
	return tray.SetVisible(true)
}

func (a *app) showMainWindow() {
	a.mw.Show()
	win.ShowWindow(a.mw.Handle(), win.SW_RESTORE)
	forceForeground(a.mw.Handle())
}

func (a *app) exit() {
	a.exiting = true
	a.mw.Close()
}

func (a *app) shutdown() {
	a.closeApprovalWindow()
	if a.hotkeys != nil {
		a.hotkeys.Close()
	}
	if a.tray != nil {
		a.tray.Dispose()
	}
	// Detach cleanly so Windows removes the device right away.
	a.service.Stop()
}

func (a *app) notify(title, message string) {
	if a.tray != nil {
		a.tray.ShowInfo(title, message)
	}
}

func (a *app) saveSettings() {
	if err := a.settings.Save(); err != nil {
		a.service.Log.Printf("Could not save settings: %v", err)
	}
}

// startAuthenticator starts the USB/IP server and, if enabled, attaches it.
func (a *app) startAuthenticator() {
	if err := a.service.Start(); err != nil {
		a.refreshStatus()
		return
	}
	if a.settings.AutoAttach {
		go a.service.AutoAttach(context.Background())
	}
}

func (a *app) onStartStop() {
	if a.service.Status().Running {
		a.startButton.SetEnabled(false)
		go func() {
			a.service.Stop()
			a.mw.Synchronize(func() { a.startButton.SetEnabled(true) })
		}()
		return
	}
	a.startAuthenticator()
}

func (a *app) onAttach() {
	go func() {
		if err := a.service.Attach(context.Background()); err != nil {
			a.mw.Synchronize(func() {
				a.notify("Could not attach", err.Error())
			})
		}
	}()
}

// pollLoop refreshes the status (driver installed?) and the log view.
func (a *app) pollLoop() {
	for range time.Tick(time.Second) {
		status := a.service.Status() // may run the usbip version probe: keep it off the UI thread
		a.mw.Synchronize(func() {
			a.applyStatus(status)
			a.refreshCredentials()
			a.refreshLog()
		})
	}
}

func (a *app) refreshStatus() {
	a.applyStatus(a.service.Status())
}

func (a *app) applyStatus(status desktop.Status) {
	text, detail, icon := "", "", a.icons.stopped
	switch {
	case !status.Unlocked:
		text = "Locked"
	case a.approval != nil:
		text, icon = "Waiting for your approval…", a.icons.attention
	case !status.Running:
		text = "Stopped"
		detail = status.LastError
	case status.HostAttached:
		text, icon = "Ready — Windows can use your security key", a.icons.normal
	case status.Attaching:
		text, icon = "Attaching to Windows…", a.icons.normal
	case !status.Driver.Found:
		text = "Not attached: Windows needs the free usbip-win2 driver"
		detail = "Install it (Get the USB/IP driver…), then click Attach."
	default:
		text = "Running, but not attached to Windows"
		detail = "Click Attach."
		if status.LastError != "" {
			detail = status.LastError
		}
	}
	if detail == "" && status.Running {
		detail = "Driver: " + status.Driver.String()
		if status.AttachedPort > 0 {
			detail += fmt.Sprintf(" · virtual USB port %d", status.AttachedPort)
		}
	}
	a.statusText.SetText(text)
	a.statusDetail.SetText(detail)
	a.driverButton.SetVisible(status.Running && !status.Driver.Found)
	a.attachButton.SetEnabled(status.Running && !status.HostAttached && !status.Attaching && status.Driver.Found)
	if status.Running {
		a.startButton.SetText("Stop")
	} else {
		a.startButton.SetText("Start")
	}
	a.startButton.SetEnabled(status.Unlocked)
	if a.tray != nil {
		if a.approval == nil {
			a.tray.SetIcon(icon)
		}
		a.tray.SetToolTip(truncate(mainWindowTitle+": "+text, 120))
	}
	if a.shown != icon {
		a.shown = icon
		a.mw.SetIcon(icon)
		a.statusImage.SetImage(icon)
	}

	switch {
	case !status.PINSupported:
		a.pinStatus.SetText("PIN protection is turned off.")
	case status.PINSet && status.PINRetries == 0:
		a.pinStatus.SetText("The PIN is blocked after too many wrong attempts. Remove it or set a new one.")
	case status.PINSet:
		a.pinStatus.SetText(fmt.Sprintf("A PIN is set (%d attempts left).", status.PINRetries))
	default:
		a.pinStatus.SetText("No PIN yet.")
	}
	if status.PINSet {
		a.setPINButton.SetText("Change PIN…")
	} else {
		a.setPINButton.SetText("Set PIN…")
	}
	a.clearPINButton.SetEnabled(status.PINSet)
	a.pinSupport.SetChecked(status.PINSupported)
}

func (a *app) refreshLog() {
	lines, version := a.service.Log.Snapshot()
	if version == a.logVersion {
		return
	}
	a.logVersion = version
	if len(lines) > 400 {
		lines = lines[len(lines)-400:]
	}
	a.logView.SetText(strings.Join(lines, "\r\n"))
	end := a.logView.TextLength()
	a.logView.SetTextSelection(end, end)
	a.logView.ScrollToCaret()
}

func (a *app) loadSettingsIntoUI() {
	setCombo := func(combo *walk.ComboBox, value string) {
		if value == "" {
			value = "(none)"
		}
		combo.SetText(value)
	}
	setCombo(a.approveHotkey, a.settings.ApproveHotkey)
	setCombo(a.denyHotkey, a.settings.DenyHotkey)
	a.timeoutEdit.SetValue(float64(a.settings.ApprovalTimeoutSeconds))
	a.rememberCheck.SetChecked(len(a.settings.ProtectedPassphrase) > 0)
	a.autoAttachCheck.SetChecked(a.settings.AutoAttach)
	a.minimizedCheck.SetChecked(a.settings.StartMinimized)
	a.signInCheck.SetChecked(runAtSignIn())
}

func hotkeyText(combo *walk.ComboBox) string {
	text := strings.TrimSpace(combo.Text())
	if text == "(none)" {
		return ""
	}
	return text
}

// applyHotkeys registers the saved hotkeys and shows the result.
func (a *app) applyHotkeys() {
	approve, err1 := desktop.ParseHotkey(a.settings.ApproveHotkey)
	deny, err2 := desktop.ParseHotkey(a.settings.DenyHotkey)
	var problems []string
	for _, err := range []error{err1, err2} {
		if err != nil {
			problems = append(problems, err.Error())
		}
	}
	errs := a.hotkeys.Set(approve, deny)
	a.approveHotkeyActive = ""
	if err := errs[hotkeyApprove]; err != nil {
		problems = append(problems, "Approve hotkey: "+err.Error())
	} else if approve != nil {
		a.approveHotkeyActive = a.settings.ApproveHotkey
	}
	if err := errs[hotkeyDeny]; err != nil {
		problems = append(problems, "Deny hotkey: "+err.Error())
	}
	if len(problems) > 0 {
		a.hotkeyStatus.SetTextColor(colorRed)
		a.hotkeyStatus.SetText(strings.Join(problems, " "))
		return
	}
	a.hotkeyStatus.SetTextColor(colorGreen)
	switch {
	case approve != nil:
		a.hotkeyStatus.SetText("Hotkeys active.")
	default:
		a.hotkeyStatus.SetText("No approve hotkey: use the pop-up.")
	}
}

func (a *app) onApplyApprovalSettings() {
	approve, deny := hotkeyText(a.approveHotkey), hotkeyText(a.denyHotkey)
	for _, text := range []string{approve, deny} {
		if _, err := desktop.ParseHotkey(text); err != nil {
			a.hotkeyStatus.SetTextColor(colorRed)
			a.hotkeyStatus.SetText(err.Error())
			return
		}
	}
	if approve != "" && strings.EqualFold(approve, deny) {
		a.hotkeyStatus.SetTextColor(colorRed)
		a.hotkeyStatus.SetText("Approve and deny need different hotkeys.")
		return
	}
	a.settings.ApproveHotkey, a.settings.DenyHotkey = approve, deny
	a.settings.ApprovalTimeoutSeconds = int(a.timeoutEdit.Value())
	a.service.Approvals.SetTimeout(time.Duration(a.settings.ApprovalTimeoutSeconds) * time.Second)
	a.saveSettings()
	a.applyHotkeys()
}

func (a *app) onPINSupport() {
	if err := a.service.SetPINSupport(a.pinSupport.Checked()); err != nil {
		walk.MsgBox(a.mw, mainWindowTitle, err.Error(), walk.MsgBoxIconError)
	}
}

func (a *app) onClearPIN() {
	if walk.MsgBox(a.mw, mainWindowTitle, "Remove the PIN? Websites that require it will ask Windows to set a new one.",
		walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	if err := a.service.ClearPIN(); err != nil {
		walk.MsgBox(a.mw, mainWindowTitle, err.Error(), walk.MsgBoxIconError)
	}
}

func (a *app) onRememberToggled() {
	if !a.rememberCheck.Checked() {
		a.rememberPassphrase(false, "")
		return
	}
	passphrase, err := a.service.Passphrase()
	if err != nil {
		a.rememberCheck.SetChecked(false)
		return
	}
	a.rememberPassphrase(true, passphrase)
}

func (a *app) onGeneralSetting() {
	a.settings.AutoAttach = a.autoAttachCheck.Checked()
	a.settings.StartMinimized = a.minimizedCheck.Checked()
	a.saveSettings()
}

func (a *app) onSignInToggled() {
	if err := setRunAtSignIn(a.signInCheck.Checked()); err != nil {
		walk.MsgBox(a.mw, mainWindowTitle, "Could not change the startup setting: "+err.Error(), walk.MsgBoxIconError)
		a.signInCheck.SetChecked(runAtSignIn())
	}
}

// credentialModel feeds the passkey table.
type credentialModel struct {
	walk.TableModelBase
	items []desktop.CredentialInfo
}

func (m *credentialModel) RowCount() int { return len(m.items) }

func (m *credentialModel) Value(row, col int) interface{} {
	item := m.items[row]
	switch col {
	case 0:
		if item.SiteName != "" && item.SiteName != item.Site {
			return fmt.Sprintf("%s (%s)", item.Site, item.SiteName)
		}
		return item.Site
	case 1:
		return item.UserName
	case 2:
		if item.Passkey {
			return "Passkey"
		}
		return "Security key"
	case 3:
		return item.SignCount
	}
	return ""
}

func (a *app) refreshCredentials() {
	items := a.service.Credentials()
	same := len(items) == len(a.credentialModel.items)
	for i := 0; same && i < len(items); i++ {
		same = bytes.Equal(items[i].ID, a.credentialModel.items[i].ID) && items[i].SignCount == a.credentialModel.items[i].SignCount
	}
	if same {
		return
	}
	a.credentialModel.items = items
	a.credentialModel.PublishRowsReset()
	a.updateCredentialButtons()
}

func (a *app) updateCredentialButtons() {
	index := a.credentialTable.CurrentIndex()
	a.deleteButton.SetEnabled(index >= 0 && index < len(a.credentialModel.items))
}

func (a *app) onDeleteCredential() {
	index := a.credentialTable.CurrentIndex()
	if index < 0 || index >= len(a.credentialModel.items) {
		return
	}
	item := a.credentialModel.items[index]
	message := fmt.Sprintf("Delete the passkey for %s (%s)?\n\nYou will no longer be able to sign in to %s with it. This cannot be undone.",
		item.Site, item.UserName, item.Site)
	if walk.MsgBox(a.mw, mainWindowTitle, message, walk.MsgBoxYesNo|walk.MsgBoxIconWarning) != walk.DlgCmdYes {
		return
	}
	if err := a.service.DeleteCredential(item.ID); err != nil {
		walk.MsgBox(a.mw, mainWindowTitle, err.Error(), walk.MsgBoxIconError)
	}
	a.refreshCredentials()
}

func truncate(text string, max int) string {
	if len(text) <= max {
		return text
	}
	return text[:max-1] + "…"
}
