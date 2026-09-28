//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/bulwarkid/virtual-fido/desktop"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	user32                = windows.NewLazySystemDLL("user32.dll")
	procRegisterHotKey    = user32.NewProc("RegisterHotKey")
	procUnregisterHotKey  = user32.NewProc("UnregisterHotKey")
	procPostThreadMessage = user32.NewProc("PostThreadMessageW")
	procFlashWindowEx     = user32.NewProc("FlashWindowEx")
)

const (
	wmHotkey      = 0x0312
	wmApplyHotkey = win.WM_APP + 1
	wmQuit        = 0x0012

	hotkeyApprove = 1
	hotkeyDeny    = 2
)

// hotkeyManager owns a thread with a message loop that receives WM_HOTKEY for
// global hotkeys registered with RegisterHotKey (hotkeys are tied to the
// thread that registered them).
type hotkeyManager struct {
	threadID uint32
	onHotkey func(id int)

	mu      sync.Mutex
	pending map[int]*desktop.Hotkey
	result  chan map[int]error
	done    chan struct{}
}

func startHotkeyManager(onHotkey func(id int)) *hotkeyManager {
	m := &hotkeyManager{onHotkey: onHotkey, result: make(chan map[int]error, 1), done: make(chan struct{})}
	ready := make(chan struct{})
	go m.loop(ready)
	<-ready
	return m
}

func (m *hotkeyManager) loop(ready chan struct{}) {
	runtime.LockOSThread()
	defer close(m.done)
	m.threadID = windows.GetCurrentThreadId()
	var msg win.MSG
	// Create the thread's message queue before anyone posts to it.
	win.PeekMessage(&msg, 0, win.WM_USER, win.WM_USER, win.PM_NOREMOVE)
	close(ready)
	registered := map[int]bool{}
	for win.GetMessage(&msg, 0, 0, 0) > 0 {
		switch msg.Message {
		case wmHotkey:
			m.onHotkey(int(msg.WParam))
		case wmApplyHotkey:
			for id := range registered {
				procUnregisterHotKey.Call(0, uintptr(id))
			}
			registered = map[int]bool{}
			m.mu.Lock()
			pending := m.pending
			m.mu.Unlock()
			errs := map[int]error{}
			for id, hotkey := range pending {
				if hotkey == nil {
					continue
				}
				ok, _, err := procRegisterHotKey.Call(0, uintptr(id), uintptr(hotkey.Modifiers|desktop.ModNoRepeat), uintptr(hotkey.Key))
				if ok == 0 {
					errs[id] = fmt.Errorf("could not register the hotkey (another program may be using it): %v", err)
				} else {
					registered[id] = true
				}
			}
			m.result <- errs
		}
	}
	for id := range registered {
		procUnregisterHotKey.Call(0, uintptr(id))
	}
}

// Set registers the approve and deny hotkeys (nil disables one) and reports
// per-hotkey registration errors.
func (m *hotkeyManager) Set(approve, deny *desktop.Hotkey) map[int]error {
	m.mu.Lock()
	m.pending = map[int]*desktop.Hotkey{hotkeyApprove: approve, hotkeyDeny: deny}
	m.mu.Unlock()
	if ok, _, err := procPostThreadMessage.Call(uintptr(m.threadID), wmApplyHotkey, 0, 0); ok == 0 {
		return map[int]error{hotkeyApprove: fmt.Errorf("hotkey thread unavailable: %v", err)}
	}
	select {
	case errs := <-m.result:
		return errs
	case <-time.After(2 * time.Second):
		return map[int]error{hotkeyApprove: errors.New("timed out registering hotkeys")}
	}
}

func (m *hotkeyManager) Close() {
	procPostThreadMessage.Call(uintptr(m.threadID), wmQuit, 0, 0)
	select {
	case <-m.done:
	case <-time.After(time.Second):
	}
}

var instanceMutex windows.Handle

// acquireSingleInstance returns false if Virtual FIDO is already running
// (only one copy can own the USB/IP port).
func acquireSingleInstance() bool {
	name, _ := windows.UTF16PtrFromString(`Local\VirtualFIDO-SingleInstance`)
	handle, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		windows.CloseHandle(handle)
		return false
	}
	instanceMutex = handle
	return true
}

// showExistingInstance brings the already-running copy's window forward.
func showExistingInstance() {
	title, _ := syscall.UTF16PtrFromString(mainWindowTitle)
	if hwnd := win.FindWindow(nil, title); hwnd != 0 {
		win.ShowWindow(hwnd, win.SW_SHOW)
		win.ShowWindow(hwnd, win.SW_RESTORE)
		forceForeground(hwnd)
	}
}

// forceForeground raises a window above the browser's security-key dialog.
// Windows only lets the foreground process move focus, so attach to its
// input queue briefly (the standard workaround).
func forceForeground(hwnd win.HWND) {
	foreground := win.GetForegroundWindow()
	current := windows.GetCurrentThreadId()
	target := win.GetWindowThreadProcessId(foreground, nil)
	if foreground != 0 && target != current {
		win.AttachThreadInput(int32(current), int32(target), true)
		defer win.AttachThreadInput(int32(current), int32(target), false)
	}
	win.BringWindowToTop(hwnd)
	win.SetForegroundWindow(hwnd)
}

func setTopmost(hwnd win.HWND) {
	win.SetWindowPos(hwnd, win.HWND_TOPMOST, 0, 0, 0, 0, win.SWP_NOMOVE|win.SWP_NOSIZE|win.SWP_SHOWWINDOW)
}

type flashWInfo struct {
	cbSize    uint32
	hwnd      win.HWND
	dwFlags   uint32
	uCount    uint32
	dwTimeout uint32
}

// flashWindow flashes the window's taskbar button until it is activated.
func flashWindow(hwnd win.HWND) {
	const flashwAll, flashwTimerNoFG = 0x3, 0xC
	info := flashWInfo{hwnd: hwnd, dwFlags: flashwAll | flashwTimerNoFG}
	info.cbSize = uint32(unsafe.Sizeof(info))
	procFlashWindowEx.Call(uintptr(unsafe.Pointer(&info)))
}

// openURL opens a link or folder with its default handler.
func openURL(target string) {
	verb, _ := syscall.UTF16PtrFromString("open")
	file, _ := syscall.UTF16PtrFromString(target)
	win.ShellExecute(0, verb, file, nil, nil, win.SW_SHOWNORMAL)
}

const (
	runKeyPath   = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValueName = "VirtualFIDO"
)

// runAtSignIn reports whether Windows starts Virtual FIDO at sign-in.
func runAtSignIn() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	_, _, err = key.GetStringValue(runValueName)
	return err == nil
}

// setRunAtSignIn adds or removes the per-user Run entry (starts minimized).
func setRunAtSignIn(enabled bool) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if !enabled {
		err := key.DeleteValue(runValueName)
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return key.SetStringValue(runValueName, fmt.Sprintf("%q --minimized", exe))
}
