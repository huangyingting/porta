//go:build windows

package winnetwork

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestProtectedDirectoryPinsOnlyDirectoryAndAllowsJournalUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "protected")
	pin, err := PrepareProtectedDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	if err := os.Rename(path, path+"-moved"); err == nil {
		t.Fatal("directory pin allowed rename")
	}
	runner, err := NewRunner(filepath.Join(path, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner.state = networkState{Version: 2, Interface: "Porta", GuardKey: objectKey("test", -2),
		ServerIP: "192.0.2.1", Endpoint: endpoint{IP: netip.MustParseAddr("192.0.2.1"), Port: 443}}
	for _, name := range []string{"Porta", "Porta updated", "Porta replaced again"} {
		runner.state.Interface = name
		if err := runner.persistLocked(); err != nil {
			t.Fatal(err)
		}
		if err := runner.reloadLocked(); err != nil || runner.state.Interface != name {
			t.Fatalf("repeated update: %v, %+v", err, runner.state)
		}
	}
	before, err := os.ReadFile(runner.statePath)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenProtectedFile(runner.statePath, false)
	if err != nil {
		t.Fatal(err)
	}
	runner.state.Interface = "must not replace"
	err = runner.persistLocked()
	reader.Close()
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("expected Windows sharing/access denial, got %v", err)
	}
	after, err := os.ReadFile(runner.statePath)
	if err != nil || string(after) != string(before) {
		t.Fatalf("denied update destroyed old recovery bytes: %v", err)
	}
	if _, err := os.Lstat(runner.statePath + ".pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed publication left a pending file: %v", err)
	}
	if err := runner.persistLocked(); err != nil {
		t.Fatalf("unlocked retry: %v", err)
	}
}

func TestProtectedFilesRejectLinksAndUnprotectedFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenProtectedFile(target, false); err == nil {
		t.Fatal("adopted a user-writable file")
	}
	if err := os.Link(target, link); err != nil {
		t.Fatal(err)
	}
	if err := RemoveProtectedFile(link); err == nil {
		t.Fatal("removed a hard-linked privileged file")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "unchanged" {
		t.Fatal("hard link target changed")
	}
}

func TestNetworkCommandIgnoresUntrustedEnvironment(t *testing.T) {
	t.Setenv("SystemRoot", `C:\attacker`)
	t.Setenv("PSModulePath", `C:\attacker\modules`)
	t.Setenv("PATH", `C:\attacker`)
	path := `C:\ProgramData\Porta\state.json`
	command, err := networkCommand(context.Background(), path, []string{"down", path})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(command.Env, "\n")+command.Path+command.Dir, "attacker") {
		t.Fatal("network helper inherited user-controlled executable/module lookup")
	}
	if command.Stdin == nil || strings.Contains(strings.Join(command.Args, " "), path) {
		t.Fatal("network helper did not separate code from argument data")
	}
	for _, args := range [][]string{{}, {"unknown", path}, {"down", `C:\other`}, {"down", path, "extra"}} {
		if _, err := networkCommand(context.Background(), path, args); err == nil {
			t.Fatalf("accepted invalid helper arguments: %v", args)
		}
	}
}

func TestHeldJournalRevalidatesSharedRootAfterLegacyIdentityACLUpdate(t *testing.T) {
	runner := testRunner(t)
	if err := runner.Up(context.Background(), "Porta", testRemote(), testLease()); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(filepath.Dir(runner.statePath), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateProtectedDirectory(runner.directory); err == nil {
		t.Fatal("legacy identity ACL update was not detected")
	}
	lock := runner.lock
	if err := runner.acquireLocked(); err != nil {
		t.Fatal(err)
	}
	if runner.lock != lock {
		t.Fatal("ACL repair released network ownership")
	}
	if err := ValidateProtectedDirectory(runner.directory); err != nil {
		t.Fatalf("shared root was not resecured: %v", err)
	}
}
