//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/huangyingting/porta/internal/buildinfo"
	"github.com/huangyingting/porta/internal/clientapp"
	"github.com/huangyingting/porta/internal/clientid"
	"github.com/huangyingting/porta/internal/clientprofile"
	"github.com/huangyingting/porta/internal/tunnel"
	"github.com/huangyingting/porta/internal/winnetwork"
	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
)

const trayMessage co.WM = co.WM_APP + 1

type application struct {
	window      *ui.Main
	profiles    *ui.ComboBox
	name        *ui.Edit
	server      *ui.Edit
	clientID    *ui.Edit
	transport   *ui.ComboBox
	token       *ui.Edit
	status      *ui.Static
	address     *ui.Static
	duration    *ui.Static
	upload      *ui.Static
	download    *ui.Static
	logs        *ui.Edit
	connect     *ui.Button
	save        *ui.Button
	remove      *ui.Button
	store       *clientprofile.Store
	network     *winnetwork.Runner
	items       []clientprofile.Profile
	selectedID  string
	cancel      context.CancelFunc
	running     bool
	closing     bool
	connectedAt time.Time
	logLines    []string
	logPath     string
	tray        win.NOTIFYICONDATA
	mu          sync.Mutex
}

func main() {
	runtime.LockOSThread()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "porta:", err)
		os.Exit(1)
	}
}

func run() error {
	dataDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("locate profile directory: %w", err)
	}
	dataDir = filepath.Join(dataDir, "Porta")
	store, err := clientprofile.Open(filepath.Join(dataDir, "profiles.json"), clientprofile.DPAPIProtector{})
	if err != nil {
		return err
	}
	network, err := winnetwork.NewRunner(filepath.Join(dataDir, "network-state.json"))
	if err != nil {
		return err
	}
	app := newApplication(store, network, filepath.Join(dataDir, "porta.log"))
	app.window.RunAsMain()
	return nil
}

func newApplication(store *clientprofile.Store, network *winnetwork.Runner, logPath string) *application {
	window := ui.NewMain(
		ui.OptsMain().
			Title("Porta " + buildinfo.Version).
			Size(ui.Dpi(620, 650)).
			ClassIconId(101).
			Style(co.WS_CAPTION | co.WS_SYSMENU | co.WS_CLIPCHILDREN | co.WS_BORDER |
				co.WS_VISIBLE | co.WS_MINIMIZEBOX),
	)
	app := &application{window: window, store: store, network: network, logPath: logPath}

	ui.NewStatic(window, ui.OptsStatic().Text("PORTA").Position(ui.Dpi(24, 20)).Size(ui.Dpi(100, 24)))
	ui.NewStatic(window, ui.OptsStatic().Text("Secure connection profiles · v"+buildinfo.Version).Position(ui.Dpi(24, 45)).Size(ui.Dpi(240, 20)))
	app.profiles = ui.NewComboBox(window, ui.OptsComboBox().
		Position(ui.Dpi(24, 78)).Width(ui.DpiX(390)).Texts("New profile").Select(0))
	newButton := ui.NewButton(window, ui.OptsButton().Text("New").Position(ui.Dpi(426, 77)).Width(ui.DpiX(74)))
	app.remove = ui.NewButton(window, ui.OptsButton().Text("Delete").Position(ui.Dpi(510, 77)).Width(ui.DpiX(74)))

	ui.NewStatic(window, ui.OptsStatic().Text("Profile name").Position(ui.Dpi(24, 120)))
	app.name = ui.NewEdit(window, ui.OptsEdit().Position(ui.Dpi(24, 140)).Width(ui.DpiX(270)).Height(ui.DpiY(25)))
	ui.NewStatic(window, ui.OptsStatic().Text("Transport").Position(ui.Dpi(310, 120)))
	app.transport = ui.NewComboBox(window, ui.OptsComboBox().
		Position(ui.Dpi(310, 140)).Width(ui.DpiX(274)).Texts("Automatic (HTTP/3)", "HTTP/2").Select(0))

	ui.NewStatic(window, ui.OptsStatic().Text("Gateway URL").Position(ui.Dpi(24, 178)))
	app.server = ui.NewEdit(window, ui.OptsEdit().Position(ui.Dpi(24, 198)).Width(ui.DpiX(560)).Height(ui.DpiY(25)))
	ui.NewStatic(window, ui.OptsStatic().Text("Device ID").Position(ui.Dpi(24, 236)))
	app.clientID = ui.NewEdit(window, ui.OptsEdit().Position(ui.Dpi(24, 256)).Width(ui.DpiX(270)).Height(ui.DpiY(25)))
	ui.NewStatic(window, ui.OptsStatic().Text("Client token").Position(ui.Dpi(310, 236)))
	app.token = ui.NewEdit(window, ui.OptsEdit().
		Position(ui.Dpi(310, 256)).Width(ui.DpiX(274)).Height(ui.DpiY(25)).
		CtrlStyle(co.ES_LEFT|co.ES_AUTOHSCROLL|co.ES_PASSWORD))

	app.save = ui.NewButton(window, ui.OptsButton().Text("Save profile").Position(ui.Dpi(24, 296)).Width(ui.DpiX(126)))
	app.connect = ui.NewButton(window, ui.OptsButton().Text("Connect").Position(ui.Dpi(458, 296)).Width(ui.DpiX(126)))

	ui.NewStatic(window, ui.OptsStatic().Text("CONNECTION").Position(ui.Dpi(24, 348)).Size(ui.Dpi(120, 18)))
	app.status = ui.NewStatic(window, ui.OptsStatic().Text("Disconnected").Position(ui.Dpi(24, 372)).Size(ui.Dpi(250, 24)))
	app.address = ui.NewStatic(window, ui.OptsStatic().Text("Address  —").Position(ui.Dpi(310, 372)).Size(ui.Dpi(274, 20)))
	app.duration = ui.NewStatic(window, ui.OptsStatic().Text("Duration  —").Position(ui.Dpi(310, 396)).Size(ui.Dpi(274, 20)))
	app.upload = ui.NewStatic(window, ui.OptsStatic().Text("Upload  0 B").Position(ui.Dpi(24, 410)).Size(ui.Dpi(250, 22)))
	app.download = ui.NewStatic(window, ui.OptsStatic().Text("Download  0 B").Position(ui.Dpi(310, 426)).Size(ui.Dpi(274, 22)))

	ui.NewStatic(window, ui.OptsStatic().Text("ACTIVITY LOG").Position(ui.Dpi(24, 466)).Size(ui.Dpi(120, 18)))
	app.logs = ui.NewEdit(window, ui.OptsEdit().
		Position(ui.Dpi(24, 490)).Width(ui.DpiX(560)).Height(ui.DpiY(125)).
		CtrlStyle(co.ES_LEFT|co.ES_MULTILINE|co.ES_AUTOVSCROLL|co.ES_READONLY).
		WndStyle(co.WS_CHILD|co.WS_VISIBLE|co.WS_VSCROLL))

	app.profiles.On().CbnSelChange(app.selectProfile)
	newButton.On().BnClicked(app.newProfile)
	app.save.On().BnClicked(func() { app.saveProfile() })
	app.remove.On().BnClicked(app.deleteProfile)
	app.connect.On().BnClicked(app.toggleConnection)
	window.On().WmCreate(func(ui.WmCreate) int {
		app.addTray()
		profiles := app.store.List()
		if len(profiles) == 0 {
			app.reloadProfiles("")
			app.newProfile()
		} else {
			app.reloadProfiles(profiles[0].ID)
		}
		return 0
	})
	window.On().Wm(trayMessage, app.trayEvent)
	window.On().WmClose(app.close)
	window.On().WmDestroy(func() { _ = win.Shell_NotifyIcon(co.NIM_DELETE, &app.tray) })
	return app
}

func (a *application) reloadProfiles(selectID string) {
	a.items = a.store.List()
	a.profiles.DeleteAllItems()
	a.profiles.AddItem("New profile")
	selected := 0
	for index, profile := range a.items {
		a.profiles.AddItem(profile.Name)
		if profile.ID == selectID {
			selected = index + 1
		}
	}
	a.profiles.SelectIndex(selected)
	if selected > 0 {
		a.loadProfile(a.items[selected-1])
	}
}

func (a *application) selectProfile() {
	index := a.profiles.SelectedIndex()
	if index <= 0 || index > len(a.items) {
		a.newProfile()
		return
	}
	a.loadProfile(a.items[index-1])
}

func (a *application) loadProfile(profile clientprofile.Profile) {
	a.selectedID = profile.ID
	a.name.SetText(profile.Name)
	a.server.SetText(profile.ServerURL)
	a.clientID.SetText(profile.ClientID)
	a.token.SetText("")
	if profile.Transport == tunnel.TransportHTTP2 {
		a.transport.SelectIndex(1)
	} else {
		a.transport.SelectIndex(0)
	}
	a.appendLog("Selected profile " + profile.Name)
}

func (a *application) newProfile() {
	if a.running {
		return
	}
	a.selectedID = ""
	a.profiles.SelectIndex(0)
	a.name.SetText("")
	a.server.SetText("https://")
	a.clientID.SetText(defaultClientID())
	a.transport.SelectIndex(0)
	a.token.SetText("")
	a.name.Hwnd().SetFocus()
}

func (a *application) profileFromFields() clientprofile.Profile {
	transport := tunnel.TransportHTTP3
	if a.transport.SelectedIndex() == 1 {
		transport = tunnel.TransportHTTP2
	}
	return clientprofile.Profile{
		ID:                a.selectedID,
		Name:              strings.TrimSpace(a.name.Text()),
		ServerURL:         strings.TrimSpace(a.server.Text()),
		ClientID:          strings.TrimSpace(a.clientID.Text()),
		Transport:         transport,
		Reconnect:         true,
		ReconnectMaxDelay: 30 * time.Second,
	}
}

func (a *application) saveProfile() bool {
	if a.running {
		return false
	}
	profile, err := a.store.Save(a.profileFromFields(), strings.TrimSpace(a.token.Text()))
	if err != nil {
		a.showError(err)
		return false
	}
	a.selectedID = profile.ID
	a.token.SetText("")
	a.reloadProfiles(profile.ID)
	a.appendLog("Saved profile " + profile.Name)
	return true
}

func (a *application) deleteProfile() {
	if a.running || a.selectedID == "" {
		return
	}
	answer, _ := a.window.Hwnd().MessageBox(
		"Delete this profile and its protected client token?",
		"Porta",
		co.MB_YESNO|co.MB_ICONWARNING,
	)
	if answer != co.ID_YES {
		return
	}
	if err := a.store.Delete(a.selectedID); err != nil {
		a.showError(err)
		return
	}
	a.appendLog("Deleted profile")
	a.reloadProfiles("")
	a.newProfile()
}

func (a *application) toggleConnection() {
	a.mu.Lock()
	if a.running {
		cancel := a.cancel
		a.mu.Unlock()
		setText(a.status, "Disconnecting")
		a.connect.SetText("Disconnecting…")
		a.connect.Hwnd().EnableWindow(false)
		cancel()
		return
	}
	a.mu.Unlock()

	if !a.saveProfile() || a.selectedID == "" {
		return
	}
	token, err := a.store.Token(a.selectedID)
	if err != nil {
		a.showError(err)
		return
	}
	profile := a.profileFromFields()
	ctx, cancel := context.WithCancel(context.Background())
	a.mu.Lock()
	a.running = true
	a.cancel = cancel
	a.mu.Unlock()
	a.setEditing(false)
	a.connect.SetText("Cancel")
	a.appendLog("Connecting to " + profile.ServerURL)
	go func() {
		err := clientapp.Run(ctx, clientapp.Config{
			ServerURL:         profile.ServerURL,
			Token:             token,
			ClientID:          profile.ClientID,
			Transport:         profile.Transport,
			InterfaceName:     "Porta",
			Reconnect:         profile.Reconnect,
			ReconnectMaxDelay: profile.ReconnectMaxDelay,
			Network:           a.network,
		}, a.handleEvent)
		a.window.UiThread(func() {
			a.mu.Lock()
			a.running = false
			a.cancel = nil
			closing := a.closing
			a.mu.Unlock()
			a.setEditing(true)
			a.connect.SetText("Connect")
			a.connect.Hwnd().EnableWindow(true)
			if err != nil && !errors.Is(err, context.Canceled) {
				a.appendLog("Error: " + err.Error())
				setText(a.status, "Error")
			} else {
				setText(a.status, "Disconnected")
			}
			if closing {
				a.window.Hwnd().DestroyWindow()
			}
		})
	}()
}

func (a *application) handleEvent(event clientapp.Event) {
	a.window.UiThread(func() {
		setText(a.status, event.Message)
		a.updateTray(event.Message)
		if event.State == clientapp.StateConnected {
			a.connectedAt = event.ConnectedAt
			a.connect.SetText("Disconnect")
		}
		if event.Lease.Address.IsValid() {
			setText(a.address, "Address  "+event.Lease.Address.String())
		}
		if !event.ConnectedAt.IsZero() {
			setText(a.duration, "Duration  "+formatDuration(time.Since(event.ConnectedAt)))
		}
		setText(a.upload, "Upload  "+formatBytes(event.BytesUploaded))
		setText(a.download, "Download  "+formatBytes(event.BytesDownloaded))
		if event.State != clientapp.StateConnected || event.Message != "Connected" {
			a.appendLog(event.Message)
		}
	})
}

func (a *application) setEditing(enabled bool) {
	a.profiles.Hwnd().EnableWindow(enabled)
	a.name.Hwnd().EnableWindow(enabled)
	a.server.Hwnd().EnableWindow(enabled)
	a.clientID.Hwnd().EnableWindow(enabled)
	a.transport.Hwnd().EnableWindow(enabled)
	a.token.Hwnd().EnableWindow(enabled)
	a.save.Hwnd().EnableWindow(enabled)
	a.remove.Hwnd().EnableWindow(enabled)
}

func (a *application) appendLog(message string) {
	if strings.TrimSpace(message) == "" {
		return
	}
	line := time.Now().Format("15:04:05") + "  " + message
	a.logLines = append(a.logLines, line)
	if len(a.logLines) > 200 {
		a.logLines = append([]string(nil), a.logLines[len(a.logLines)-200:]...)
	}
	a.logs.SetText(strings.Join(a.logLines, "\r\n"))
	a.logs.SetSelection(-1, -1)
	a.writeLog(line)
}

func (a *application) writeLog(line string) {
	if a.logPath == "" {
		return
	}
	if info, err := os.Stat(a.logPath); err == nil && info.Size() >= 1<<20 {
		_ = os.Rename(a.logPath, a.logPath+".1")
	}
	if err := os.MkdirAll(filepath.Dir(a.logPath), 0o700); err != nil {
		return
	}
	file, err := os.OpenFile(a.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintln(file, time.Now().Format(time.RFC3339), line)
	_ = file.Close()
}

func (a *application) showError(err error) {
	a.appendLog("Error: " + err.Error())
	_, _ = a.window.Hwnd().MessageBox(err.Error(), "Porta", co.MB_ICONERROR)
}

func (a *application) close() {
	a.mu.Lock()
	if !a.closing {
		a.mu.Unlock()
		a.window.Hwnd().ShowWindow(co.SW_HIDE)
		return
	}
	if !a.running {
		a.mu.Unlock()
		a.window.Hwnd().DestroyWindow()
		return
	}
	a.closing = true
	cancel := a.cancel
	a.mu.Unlock()
	setText(a.status, "Disconnecting")
	cancel()
}

func (a *application) addTray() {
	instance, err := win.GetModuleHandle("")
	if err != nil {
		return
	}
	icon, err := instance.LoadIcon(win.IconResId(101))
	if err != nil {
		return
	}
	a.tray = win.NOTIFYICONDATA{
		HWnd:             a.window.Hwnd(),
		UID:              1,
		UFlags:           co.NIF_MESSAGE | co.NIF_ICON | co.NIF_TIP,
		UCallbackMessage: trayMessage,
		HIcon:            icon,
	}
	a.tray.SetCbSize()
	a.tray.SetSzTip("Porta — Disconnected")
	_ = win.Shell_NotifyIcon(co.NIM_ADD, &a.tray)
}

func (a *application) updateTray(status string) {
	a.tray.SetSzTip("Porta — " + status)
	_ = win.Shell_NotifyIcon(co.NIM_MODIFY, &a.tray)
}

func (a *application) trayEvent(message ui.Wm) uintptr {
	switch co.WM(message.LParam) {
	case co.WM_LBUTTONUP, co.WM_LBUTTONDBLCLK:
		a.window.Hwnd().ShowWindow(co.SW_RESTORE)
		a.window.Hwnd().SetForegroundWindow()
	case co.WM_RBUTTONUP:
		answer, _ := a.window.Hwnd().MessageBox(
			"Open Porta again with a left click.\n\nQuit Porta and disconnect?",
			"Porta",
			co.MB_YESNO|co.MB_ICONQUESTION,
		)
		if answer == co.ID_YES {
			a.mu.Lock()
			a.closing = true
			a.mu.Unlock()
			a.close()
		}
	}
	return 0
}

func setText(label *ui.Static, value string) {
	label.Hwnd().SetWindowText(value)
}

func formatBytes(value uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	size := float64(value)
	unit := 0
	for size >= 1024 && unit < len(units)-1 {
		size /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d %s", value, units[unit])
	}
	return fmt.Sprintf("%.1f %s", size, units[unit])
}

func formatDuration(value time.Duration) string {
	value = value.Truncate(time.Second)
	hours := int(value.Hours())
	minutes := int(value.Minutes()) % 60
	seconds := int(value.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
}

func defaultClientID() string {
	return clientid.Default("porta-windows")
}
