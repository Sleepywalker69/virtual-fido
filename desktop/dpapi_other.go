//go:build !windows

package desktop

import "errors"

var errNoDPAPI = errors.New("remembering the passphrase is only supported on Windows")

func ProtectPassphrase(passphrase string) ([]byte, error) { return nil, errNoDPAPI }

func UnprotectPassphrase(blob []byte) (string, error) { return "", errNoDPAPI }
