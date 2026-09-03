package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadClientTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients")
	content := "# managed credentials\nandroid-phone=0123456789abcdef0123456789abcdef\nlaptop = abcdef0123456789abcdef0123456789\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	tokens, err := loadClientTokens(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 || tokens["android-phone"] == "" || tokens["laptop"] == "" {
		t.Fatalf("tokens = %#v", tokens)
	}
}

func TestLoadClientTokensRejectsInvalidEntries(t *testing.T) {
	for _, content := range []string{
		"bad client=0123456789abcdef\n",
		"client=short\n",
		"client=0123456789abcdef\nclient=abcdef0123456789\n",
	} {
		path := filepath.Join(t.TempDir(), "clients")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadClientTokens(path); err == nil {
			t.Fatalf("invalid content accepted: %q", content)
		}
	}
}
