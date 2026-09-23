package winnetwork

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestWintunIntegrityBeforeLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wintun.dll")
	if err := os.WriteFile(path, []byte("not a DLL"), 0o600); err != nil {
		t.Fatal(err)
	}
	if file, err := openVerifiedWintun(path); err == nil {
		file.Close()
		t.Fatal("untrusted library passed verification")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	hash := sha256.Sum256([]byte("not a DLL"))
	if err := verifyWintunHash(file, hex.EncodeToString(hash[:])); err != nil {
		t.Fatal(err)
	}
	if offset, err := file.Seek(0, 1); err != nil || offset != 0 {
		t.Fatal("verified source was not rewound for staging")
	}
	link := filepath.Join(filepath.Dir(path), "linked.dll")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if file, err := openVerifiedWintun(link); err == nil {
		file.Close()
		t.Fatal("hard-linked DLL passed the load boundary")
	}
}
