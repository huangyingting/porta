//go:build windows

package clientprofile

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

type DPAPIProtector struct{}

func (DPAPIProtector) Protect(plain []byte) ([]byte, error) {
	return cryptData(plain, true)
}

func (DPAPIProtector) Unprotect(protected []byte) ([]byte, error) {
	return cryptData(protected, false)
}

func cryptData(data []byte, protect bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("secret is empty")
	}
	input := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var output windows.DataBlob
	var err error
	if protect {
		name, nameErr := windows.UTF16PtrFromString("Porta client profile")
		if nameErr != nil {
			return nil, nameErr
		}
		err = windows.CryptProtectData(&input, name, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	} else {
		err = windows.CryptUnprotectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	result := make([]byte, output.Size)
	copy(result, unsafe.Slice(output.Data, output.Size))
	return result, nil
}
