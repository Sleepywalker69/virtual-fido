package desktop

import (
	"fmt"
	"strconv"
	"strings"
)

// Hotkey is a parsed global hotkey: Windows MOD_* modifier flags and a
// virtual-key code, ready for RegisterHotKey.
type Hotkey struct {
	Modifiers uint32
	Key       uint32
}

// Windows RegisterHotKey modifier flags.
const (
	ModAlt      uint32 = 0x0001
	ModControl  uint32 = 0x0002
	ModShift    uint32 = 0x0004
	ModWin      uint32 = 0x0008
	ModNoRepeat uint32 = 0x4000
)

var namedKeys = map[string]uint32{
	"PAUSE": 0x13, "SPACE": 0x20, "ENTER": 0x0D, "TAB": 0x09,
	"PAGEUP": 0x21, "PAGEDOWN": 0x22, "END": 0x23, "HOME": 0x24,
	"INSERT": 0x2D, "DELETE": 0x2E, "SCROLLLOCK": 0x91,
}

// SuggestedHotkeys are offered in the UI. F13-F24 do not exist on ordinary
// keyboards, which makes them ideal for a macropad key.
var SuggestedHotkeys = []string{
	"", "F13", "F14", "F15", "F16", "F17", "F18", "F19", "F20", "F21", "F22", "F23", "F24",
	"Ctrl+Alt+F12", "Ctrl+Alt+A", "Pause", "ScrollLock",
}

// ParseHotkey parses strings like "F13", "Ctrl+Alt+F12" or "Ctrl+Shift+Y".
// An empty string means "no hotkey" and returns (nil, nil).
func ParseHotkey(text string) (*Hotkey, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, nil
	}
	hotkey := &Hotkey{}
	parts := strings.Split(text, "+")
	for i, part := range parts {
		name := strings.ToUpper(strings.TrimSpace(part))
		if name == "" {
			return nil, fmt.Errorf("invalid hotkey %q", text)
		}
		if i < len(parts)-1 {
			switch name {
			case "CTRL", "CONTROL":
				hotkey.Modifiers |= ModControl
			case "ALT":
				hotkey.Modifiers |= ModAlt
			case "SHIFT":
				hotkey.Modifiers |= ModShift
			case "WIN", "WINDOWS":
				hotkey.Modifiers |= ModWin
			default:
				return nil, fmt.Errorf("unknown modifier %q in hotkey %q", part, text)
			}
			continue
		}
		key, err := parseKey(name)
		if err != nil {
			return nil, fmt.Errorf("%v in hotkey %q", err, text)
		}
		hotkey.Key = key
	}
	return hotkey, nil
}

func parseKey(name string) (uint32, error) {
	if key, ok := namedKeys[name]; ok {
		return key, nil
	}
	if len(name) == 1 {
		c := name[0]
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			return uint32(c), nil
		}
	}
	if strings.HasPrefix(name, "F") {
		if n, err := strconv.Atoi(name[1:]); err == nil && n >= 1 && n <= 24 {
			return 0x70 + uint32(n-1), nil // VK_F1..VK_F24
		}
	}
	if strings.HasPrefix(name, "NUMPAD") {
		if n, err := strconv.Atoi(name[6:]); err == nil && n >= 0 && n <= 9 {
			return 0x60 + uint32(n), nil
		}
	}
	return 0, fmt.Errorf("unknown key %q", name)
}
