//go:build windows

package desktop

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const cryptProtectUIForbidden = 0x1

// ProtectPassphrase encrypts the passphrase for the current Windows account
// (DPAPI), so only this user on this PC can decrypt it.
func ProtectPassphrase(passphrase string) ([]byte, error) {
	return dpapi([]byte(passphrase), true)
}

// UnprotectPassphrase decrypts a blob from ProtectPassphrase.
func UnprotectPassphrase(blob []byte) (string, error) {
	plain, err := dpapi(blob, false)
	return string(plain), err
}

func dpapi(data []byte, protect bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	var err error
	if protect {
		err = windows.CryptProtectData(&in, nil, nil, 0, nil, cryptProtectUIForbidden, &out)
	} else {
		err = windows.CryptUnprotectData(&in, nil, nil, 0, nil, cryptProtectUIForbidden, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
