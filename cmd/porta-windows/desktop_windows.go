//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huangyingting/porta/internal/buildinfo"
	"github.com/huangyingting/porta/internal/clientapp"
	"github.com/huangyingting/porta/internal/clientprofile"
	"github.com/huangyingting/porta/internal/tunnel"
	"github.com/huangyingting/porta/internal/winnetwork"
	"github.com/wailsapp/wails/v3/pkg/application"
)

const (
	networkActionTimeout = 20 * time.Second
	maxActivityLines     = 200
)

type ProfileInput struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	ServerURL string `json:"serverUrl"`
	Transport string `json:"transport"`
	Token     string `json:"token"`
}

type DesktopProfile struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	ServerURL string `json:"serverUrl"`
	Transport string `json:"transport"`
	Selected  bool   `json:"selected"`
	Active    bool   `json:"active"`
	Status    string `json:"status"`
}

type DesktopSnapshot struct {
	Version           string           `json:"version"`
	Profiles          []DesktopProfile `json:"profiles"`
	SelectedProfileID string           `json:"selectedProfileId"`
	ActiveProfileID   string           `json:"activeProfileId"`
	Status            string           `json:"status"`
	Detail            string           `json:"detail"`
	Tone              string           `json:"tone"`
	Running           bool             `json:"running"`
	Connected         bool             `json:"connected"`
	Restoring         bool             `json:"restoring"`
	Disconnecting     bool             `json:"disconnecting"`
	RecoveryAvailable bool             `json:"recoveryAvailable"`
	Address           string           `json:"address"`
	Transport         string           `json:"transport"`
	MTU               int              `json:"mtu"`
	ConnectedAt       string           `json:"connectedAt"`
	BytesUploaded     uint64           `json:"bytesUploaded"`
	BytesDownloaded   uint64           `json:"bytesDownloaded"`
	UploadRate        uint64           `json:"uploadRate"`
	DownloadRate      uint64           `json:"downloadRate"`
	Activity          []string         `json:"activity"`
}

type connectionDisplay struct {
	title  string
	detail string
	tone   string
}

type activityRecord struct {
	generation uint64
	line       string
}

type DesktopController struct {
	mu              sync.Mutex
	logMu           sync.Mutex
	store           *clientprofile.Store
	network         *winnetwork.Runner
	logPath         string
	app             *application.App
	window          application.Window
	tray            *application.SystemTray
	trayConnect     *application.MenuItem
	trayRestore     *application.MenuItem
	trayActivity    *application.MenuItem
	selectedID      string
	activeID        string
	cancel          context.CancelFunc
	running         bool
	connected       bool
	disconnecting   bool
	restoring       bool
	quitting        bool
	allowClose      atomic.Bool
	shutdownCommit  atomic.Bool
	recovery        bool
	status          string
	detail          string
	tone            string
	address         string
	transport       string
	mtu             int
	connectedAt     time.Time
	bytesUploaded   uint64
	bytesDownloaded uint64
	uploadRate      uint64
	downloadRate    uint64
	lastSampleAt    time.Time
	lastUploaded    uint64
	lastDownloaded  uint64
	activity        []string
	activityEpoch   uint64
	logFailure      bool
}

func newDesktopController(store *clientprofile.Store, network *winnetwork.Runner, logPath string) *DesktopController {
	controller := &DesktopController{
		store: store, network: network, logPath: logPath,
		status: "Disconnected", detail: "Choose a profile to connect securely.", tone: "offline",
	}
	profiles := store.List()
	if len(profiles) > 0 {
		controller.selectedID = profiles[0].ID
	}
	controller.activity = loadActivity(logPath)
	controller.recovery = network.NeedsCleanup()
	if controller.recovery {
		controller.status = "Network recovery available"
		controller.detail = "Reconnect to resume, or restore normal connectivity."
		controller.tone = "warning"
		controller.appendActivityLocked("Retained network protection is ready for recovery.")
	}
	return controller
}

func (d *DesktopController) attach(
	app *application.App,
	window application.Window,
	tray *application.SystemTray,
	connect, restore, activity *application.MenuItem,
) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.app = app
	d.window = window
	d.tray = tray
	d.trayConnect = connect
	d.trayRestore = restore
	d.trayActivity = activity
}

func (d *DesktopController) Snapshot() DesktopSnapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.snapshotLocked()
}

func (d *DesktopController) SelectProfile(id string) (DesktopSnapshot, error) {
	d.mu.Lock()
	if d.running && id != d.activeID {
		snapshot := d.snapshotLocked()
		d.mu.Unlock()
		return snapshot, errors.New("disconnect the active profile before selecting another one")
	}
	if _, ok := d.profileLocked(id); !ok {
		snapshot := d.snapshotLocked()
		d.mu.Unlock()
		return snapshot, errors.New("profile not found")
	}
	d.selectedID = id
	if !d.running && !d.restoring {
		if profile, ok := d.profileLocked(id); ok {
			d.status = "Ready"
			d.detail = profile.Name + " - " + profile.ServerURL
			d.tone = "offline"
		}
	}
	snapshot := d.snapshotLocked()
	d.mu.Unlock()
	d.publish()
	return snapshot, nil
}

func (d *DesktopController) SaveProfile(input ProfileInput) (DesktopSnapshot, error) {
	d.mu.Lock()
	if d.running || d.restoring {
		snapshot := d.snapshotLocked()
		d.mu.Unlock()
		return snapshot, errors.New("profiles cannot be changed while Porta is busy")
	}
	var original clientprofile.Profile
	if input.ID != "" {
		var ok bool
		original, ok = d.profileLocked(input.ID)
		if !ok {
			snapshot := d.snapshotLocked()
			d.mu.Unlock()
			return snapshot, errors.New("profile not found")
		}
	}
	profile := profileWithFields(original, clientprofile.Profile{
		ID:        strings.TrimSpace(input.ID),
		Name:      strings.TrimSpace(input.Name),
		ServerURL: strings.TrimSpace(input.ServerURL),
		Transport: tunnel.Transport(strings.TrimSpace(input.Transport)),
	})
	saved, err := d.store.Save(profile, strings.TrimSpace(input.Token))
	if err != nil {
		d.status = "Save profile failed"
		d.detail = err.Error()
		d.tone = "danger"
		d.appendActivityLocked("Save profile failed: " + err.Error())
		record := d.activityRecordLocked()
		snapshot := d.snapshotLocked()
		d.mu.Unlock()
		d.writeActivity(record)
		d.publish()
		return snapshot, err
	}
	d.selectedID = saved.ID
	d.status = "Ready"
	d.detail = saved.Name + " - " + saved.ServerURL
	d.tone = "offline"
	d.appendActivityLocked("Saved profile " + saved.Name)
	record := d.activityRecordLocked()
	snapshot := d.snapshotLocked()
	d.mu.Unlock()
	d.writeActivity(record)
	d.publish()
	return snapshot, nil
}

func (d *DesktopController) DeleteProfile(id string) (DesktopSnapshot, error) {
	d.mu.Lock()
	if d.running || d.restoring {
		snapshot := d.snapshotLocked()
		d.mu.Unlock()
		return snapshot, errors.New("profiles cannot be deleted while Porta is busy")
	}
	profile, ok := d.profileLocked(id)
	if !ok {
		snapshot := d.snapshotLocked()
		d.mu.Unlock()
		return snapshot, errors.New("profile not found")
	}
	if err := d.store.Delete(id); err != nil {
		d.status = "Delete profile failed"
		d.detail = err.Error()
		d.tone = "danger"
		d.appendActivityLocked("Delete profile failed: " + err.Error())
		record := d.activityRecordLocked()
		snapshot := d.snapshotLocked()
		d.mu.Unlock()
		d.writeActivity(record)
		d.publish()
		return snapshot, err
	}
	profiles := d.store.List()
	d.selectedID = ""
	if len(profiles) > 0 {
		d.selectedID = profiles[0].ID
		d.status = "Ready"
		d.detail = profiles[0].Name + " - " + profiles[0].ServerURL
	} else {
		d.status = "Disconnected"
		d.detail = "Add a profile to connect securely."
	}
	d.tone = "offline"
	d.appendActivityLocked("Deleted profile " + profile.Name)
	record := d.activityRecordLocked()
	snapshot := d.snapshotLocked()
	d.mu.Unlock()
	d.writeActivity(record)
	d.publish()
	return snapshot, nil
}

func (d *DesktopController) Connect(id string) error {
	d.mu.Lock()
	if d.running || d.restoring {
		d.mu.Unlock()
		return errors.New("Porta is already connecting or restoring the network")
	}
	if id == "" {
		id = d.selectedID
	}
	profile, ok := d.profileLocked(id)
	if !ok {
		d.mu.Unlock()
		return errors.New("select a profile first")
	}
	token, err := d.store.Token(profile.ID)
	if err != nil {
		d.mu.Unlock()
		d.recordError("Read protected token failed", err)
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.selectedID = profile.ID
	d.activeID = profile.ID
	d.cancel = cancel
	d.running = true
	d.connected = false
	d.disconnecting = false
	d.status = "Connecting"
	d.detail = "Establishing a secure tunnel..."
	d.tone = "warning"
	d.resetConnectionLocked()
	d.appendActivityLocked("Connecting " + profile.Name + " to " + profile.ServerURL)
	record := d.activityRecordLocked()
	d.mu.Unlock()
	d.writeActivity(record)
	d.publish()

	go d.runConnection(ctx, cancel, profile, token)
	return nil
}

func (d *DesktopController) Disconnect() error {
	d.mu.Lock()
	if d.restoring {
		d.mu.Unlock()
		return errors.New("network restoration is already in progress")
	}
	if !d.running || d.cancel == nil {
		d.mu.Unlock()
		return nil
	}
	cancel := d.cancel
	d.disconnecting = true
	d.status = "Disconnecting"
	d.detail = "Restoring normal network access..."
	d.tone = "warning"
	d.mu.Unlock()
	d.publish()
	cancel()
	return nil
}

func (d *DesktopController) ToggleConnection() error {
	d.mu.Lock()
	running := d.running
	selectedID := d.selectedID
	d.mu.Unlock()
	if running {
		return d.Disconnect()
	}
	return d.Connect(selectedID)
}

func (d *DesktopController) RestoreNetwork() error {
	return d.beginRestore(false)
}

func (d *DesktopController) ClearActivity() error {
	d.logMu.Lock()
	err := removeActivityFiles(d.logPath)
	if err != nil {
		d.logMu.Unlock()
		d.recordError("Clear activity failed", err)
		return err
	}
	d.mu.Lock()
	d.activityEpoch++
	d.activity = nil
	d.logFailure = false
	d.mu.Unlock()
	d.logMu.Unlock()
	d.publish()
	return nil
}

func (d *DesktopController) SaveActivityLog() (string, error) {
	d.mu.Lock()
	app := d.app
	window := d.window
	lines := append([]string(nil), d.activity...)
	d.mu.Unlock()
	if app == nil {
		return "", errors.New("desktop application is not ready")
	}
	path, err := app.Dialog.SaveFileWithOptions(&application.SaveFileDialogOptions{
		CanCreateDirectories: true,
		AllowOtherFileTypes:  true,
		Title:                "Save Porta activity log",
		Filename:             "porta-activity-" + time.Now().Format("20060102-150405") + ".log",
		ButtonText:           "Save",
		Filters: []application.FileFilter{
			{DisplayName: "Log files", Pattern: "*.log;*.txt"},
		},
		Window: window,
	}).PromptForSingleSelection()
	if isDialogCancellation(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("choose activity log destination: %w", err)
	}
	if path == "" {
		return "", nil
	}
	if err := exportActivity(path, lines); err != nil {
		return "", err
	}
	return path, nil
}

func (d *DesktopController) OpenLogFolder() (string, error) {
	directory := filepath.Dir(d.logPath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create activity log directory: %w", err)
	}
	if err := exec.Command("explorer.exe", directory).Start(); err != nil {
		return "", fmt.Errorf("open activity log directory: %w", err)
	}
	return directory, nil
}

func (d *DesktopController) Show() {
	d.mu.Lock()
	window := d.window
	d.mu.Unlock()
	if window != nil {
		showWindow(window)
	}
}

func (d *DesktopController) Reactivate() {
	if d.shutdownCommit.Load() {
		d.startRestartHelper()
		return
	}
	d.mu.Lock()
	if d.shutdownCommit.Load() {
		d.mu.Unlock()
		d.startRestartHelper()
		return
	}
	d.quitting = false
	d.allowClose.Store(false)
	window := d.window
	d.mu.Unlock()
	if window != nil {
		showWindow(window)
	}
}

func showWindow(window application.Window) {
	if window.IsMinimised() {
		window.UnMinimise()
	}
	window.Show().Focus()
}

func (d *DesktopController) startRestartHelper() {
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "porta: locate restart helper:", err)
		return
	}
	if err := exec.Command(executable, "--restart-after", fmt.Sprint(os.Getpid())).Start(); err != nil {
		fmt.Fprintln(os.Stderr, "porta: start restart helper:", err)
	}
}

func (d *DesktopController) Hide() {
	d.mu.Lock()
	window := d.window
	d.mu.Unlock()
	if window != nil {
		window.Hide()
	}
}

func (d *DesktopController) ShowActivity() {
	d.Show()
	d.mu.Lock()
	window := d.window
	d.mu.Unlock()
	if window != nil {
		window.EmitEvent("porta:view", "activity")
	}
}

func (d *DesktopController) Quit() {
	d.mu.Lock()
	if d.quitting {
		d.mu.Unlock()
		return
	}
	d.quitting = true
	running := d.running
	cancel := d.cancel
	recovery := d.recovery
	app := d.app
	d.mu.Unlock()
	if running && cancel != nil {
		d.mu.Lock()
		d.disconnecting = true
		d.status = "Disconnecting"
		d.detail = "Restoring normal network access before exit..."
		d.tone = "warning"
		d.mu.Unlock()
		d.publish()
		cancel()
		return
	}
	if recovery {
		if err := d.beginRestore(true); err != nil {
			d.mu.Lock()
			d.quitting = false
			d.mu.Unlock()
			d.recordError("Cannot quit safely", err)
			d.Show()
		}
		return
	}
	if app != nil {
		d.quitApplication(app)
	}
}

func (d *DesktopController) CanClose() bool {
	return d.allowClose.Load()
}

func (d *DesktopController) runConnection(
	ctx context.Context,
	cancel context.CancelFunc,
	profile clientprofile.Profile,
	token string,
) {
	defer cancel()
	err := clientapp.Run(ctx, clientapp.Config{
		ServerURL:         profile.ServerURL,
		Token:             token,
		Transport:         profile.Transport,
		InterfaceName:     "Porta",
		CAPath:            profile.CAPath,
		Thumbprint:        profile.Thumbprint,
		Reconnect:         profile.Reconnect,
		ReconnectMaxDelay: profile.ReconnectMaxDelay,
		Network:           d.network,
	}, d.handleConnectionEvent)

	recovery := d.network.NeedsCleanup()
	d.mu.Lock()
	d.running = false
	d.connected = false
	d.disconnecting = false
	d.cancel = nil
	d.activeID = ""
	d.recovery = recovery
	d.resetConnectionLocked()
	quitting := d.quitting
	if err != nil && !errors.Is(err, context.Canceled) {
		d.status = "Connection error"
		d.detail = err.Error()
		d.tone = "danger"
		d.appendActivityLocked("Connection error: " + err.Error())
	} else {
		d.status = "Disconnected"
		d.detail = "Choose a profile to reconnect securely."
		d.tone = "offline"
		d.appendActivityLocked("Disconnected")
	}
	record := d.activityRecordLocked()
	app := d.app
	d.mu.Unlock()
	d.writeActivity(record)
	d.publish()

	if quitting && canExitAfterDisconnect(err, recovery) {
		if app != nil {
			d.quitApplication(app)
		}
		return
	}
	if quitting {
		d.mu.Lock()
		d.quitting = false
		d.mu.Unlock()
		d.Show()
	}
}

func (d *DesktopController) handleConnectionEvent(event clientapp.Event) {
	display := connectionPresentation(event)
	var activity activityRecord
	d.mu.Lock()
	d.status = display.title
	d.detail = display.detail
	d.tone = display.tone
	d.connected = event.State == clientapp.StateConnected
	if event.Lease.Address.IsValid() {
		d.address = event.Lease.Address.String()
	}
	if event.Lease.MTU > 0 {
		d.mtu = event.Lease.MTU
	}
	if event.Transport != "" {
		d.transport = string(event.Transport)
	}
	if !event.ConnectedAt.IsZero() {
		d.connectedAt = event.ConnectedAt
	}
	d.updateRatesLocked(event)
	if event.State != clientapp.StateConnected || (event.Message != "" && event.Message != "Connected") {
		if d.appendActivityLocked(event.Message) {
			activity = d.activityRecordLocked()
		}
	}
	d.mu.Unlock()
	if activity.line != "" {
		d.writeActivity(activity)
	}
	d.publish()
}

func (d *DesktopController) beginRestore(exitAfter bool) error {
	d.mu.Lock()
	if exitAfter && !d.quitting {
		d.mu.Unlock()
		return nil
	}
	if d.running {
		d.mu.Unlock()
		return errors.New("disconnect before restoring retained network state")
	}
	if d.restoring {
		d.mu.Unlock()
		return errors.New("network restoration is already in progress")
	}
	d.restoring = true
	d.status = "Restoring network"
	d.detail = "Removing retained routes and leak protection..."
	d.tone = "warning"
	d.mu.Unlock()
	d.publish()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), networkActionTimeout)
		err := d.network.Down(ctx)
		cancel()
		recovery := d.network.NeedsCleanup()
		if err == nil && recovery {
			err = errors.New("network recovery remains pending")
		}
		safeExit := exitAfter && canExitAfterDisconnect(err, recovery)
		d.mu.Lock()
		d.restoring = false
		d.recovery = recovery
		app := d.app
		quitting := d.quitting
		shouldExit := safeExit && quitting
		if shouldExit && err != nil {
			d.appendActivityLocked("Network state is owned by another Porta process; exiting without changing it.")
		} else if err != nil {
			d.quitting = false
			d.status = "Network recovery failed"
			d.detail = err.Error()
			d.tone = "danger"
			d.appendActivityLocked("Network recovery failed: " + err.Error())
		} else {
			d.status = "Disconnected"
			d.detail = "Normal network access has been restored."
			d.tone = "offline"
			d.appendActivityLocked("Restored network and removed retained protection.")
		}
		record := d.activityRecordLocked()
		d.mu.Unlock()
		d.writeActivity(record)
		d.publish()
		if shouldExit {
			d.quitApplication(app)
		} else if err != nil {
			d.Show()
		} else if quitting {
			d.quitApplication(app)
		}
	}()
	return nil
}

func (d *DesktopController) quitApplication(app *application.App) {
	if app == nil {
		return
	}
	d.mu.Lock()
	if !d.quitting {
		d.mu.Unlock()
		return
	}
	d.allowClose.Store(true)
	d.shutdownCommit.Store(true)
	d.mu.Unlock()
	app.Quit()
}

func (d *DesktopController) updateRatesLocked(event clientapp.Event) {
	now := time.Now()
	if !d.lastSampleAt.IsZero() && now.After(d.lastSampleAt) {
		elapsed := now.Sub(d.lastSampleAt).Seconds()
		if event.BytesUploaded >= d.lastUploaded {
			d.uploadRate = uint64(float64(event.BytesUploaded-d.lastUploaded) / elapsed)
		}
		if event.BytesDownloaded >= d.lastDownloaded {
			d.downloadRate = uint64(float64(event.BytesDownloaded-d.lastDownloaded) / elapsed)
		}
	}
	d.lastSampleAt = now
	d.lastUploaded = event.BytesUploaded
	d.lastDownloaded = event.BytesDownloaded
	d.bytesUploaded = event.BytesUploaded
	d.bytesDownloaded = event.BytesDownloaded
}

func (d *DesktopController) resetConnectionLocked() {
	d.address = ""
	d.transport = ""
	d.mtu = 0
	d.connectedAt = time.Time{}
	d.bytesUploaded = 0
	d.bytesDownloaded = 0
	d.uploadRate = 0
	d.downloadRate = 0
	d.lastSampleAt = time.Time{}
	d.lastUploaded = 0
	d.lastDownloaded = 0
}

func (d *DesktopController) profileLocked(id string) (clientprofile.Profile, bool) {
	for _, profile := range d.store.List() {
		if profile.ID == id {
			return profile, true
		}
	}
	return clientprofile.Profile{}, false
}

func (d *DesktopController) snapshotLocked() DesktopSnapshot {
	profiles := d.store.List()
	result := DesktopSnapshot{
		Version:           buildinfo.Version,
		Profiles:          make([]DesktopProfile, 0, len(profiles)),
		SelectedProfileID: d.selectedID,
		ActiveProfileID:   d.activeID,
		Status:            d.status,
		Detail:            d.detail,
		Tone:              d.tone,
		Running:           d.running,
		Connected:         d.connected,
		Restoring:         d.restoring,
		Disconnecting:     d.disconnecting,
		RecoveryAvailable: d.recovery,
		Address:           d.address,
		Transport:         d.transport,
		MTU:               d.mtu,
		BytesUploaded:     d.bytesUploaded,
		BytesDownloaded:   d.bytesDownloaded,
		UploadRate:        d.uploadRate,
		DownloadRate:      d.downloadRate,
		Activity:          append([]string(nil), d.activity...),
	}
	if !d.connectedAt.IsZero() {
		result.ConnectedAt = d.connectedAt.UTC().Format(time.RFC3339Nano)
	}
	for _, profile := range profiles {
		status := "Ready"
		if profile.ID == d.activeID {
			status = d.status
		} else if profile.ID == d.selectedID {
			status = "Selected profile"
		} else if profile.Reconnect {
			status = "Auto reconnect enabled"
		}
		result.Profiles = append(result.Profiles, DesktopProfile{
			ID: profile.ID, Name: profile.Name, ServerURL: profile.ServerURL,
			Transport: string(profile.Transport), Selected: profile.ID == d.selectedID,
			Active: profile.ID == d.activeID && d.running, Status: status,
		})
	}
	return result
}

func (d *DesktopController) publish() {
	d.mu.Lock()
	snapshot := d.snapshotLocked()
	window := d.window
	tray := d.tray
	connectItem := d.trayConnect
	restoreItem := d.trayRestore
	activityItem := d.trayActivity
	d.mu.Unlock()
	if window != nil {
		window.EmitEvent("porta:snapshot", snapshot)
	}
	if tray != nil {
		tray.SetTooltip("Porta - " + snapshot.Status)
	}
	if connectItem != nil {
		label := "Connect"
		if snapshot.Running {
			label = "Disconnect"
		}
		connectItem.SetLabel(label).SetEnabled(
			(snapshot.Running && !snapshot.Restoring) ||
				(!snapshot.Running && !snapshot.Restoring && snapshot.SelectedProfileID != ""),
		)
	}
	if restoreItem != nil {
		restoreItem.SetEnabled(snapshot.RecoveryAvailable && !snapshot.Running && !snapshot.Restoring)
	}
	if activityItem != nil {
		activityItem.SetEnabled(true)
	}
}

func (d *DesktopController) appendActivityLocked(message string) bool {
	message = strings.TrimSpace(message)
	if message == "" {
		return false
	}
	line := time.Now().Format("15:04:05") + "  " + message
	d.activity = append(d.activity, line)
	if len(d.activity) > maxActivityLines {
		d.activity = append([]string(nil), d.activity[len(d.activity)-maxActivityLines:]...)
	}
	return true
}

func (d *DesktopController) activityRecordLocked() activityRecord {
	if len(d.activity) == 0 {
		return activityRecord{}
	}
	return activityRecord{generation: d.activityEpoch, line: d.activity[len(d.activity)-1]}
}

func (d *DesktopController) writeActivity(record activityRecord) {
	if strings.TrimSpace(record.line) == "" || d.logPath == "" {
		return
	}
	d.logMu.Lock()
	d.mu.Lock()
	current := record.generation == d.activityEpoch
	d.mu.Unlock()
	var err error
	if current {
		err = d.writeActivityFile(record.line)
	}
	d.logMu.Unlock()
	if err != nil {
		d.reportLogFailure(record.generation, err)
	}
}

func (d *DesktopController) writeActivityFile(line string) error {
	if err := os.MkdirAll(filepath.Dir(d.logPath), 0o700); err != nil {
		return err
	}
	if info, err := os.Stat(d.logPath); err == nil && info.Size() >= 1<<20 {
		if err := os.Remove(d.logPath + ".1"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(d.logPath, d.logPath+".1"); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(d.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := fmt.Fprintln(file, time.Now().Format(time.RFC3339), line)
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

func (d *DesktopController) reportLogFailure(generation uint64, err error) {
	d.mu.Lock()
	if generation != d.activityEpoch || d.logFailure {
		d.mu.Unlock()
		return
	}
	d.logFailure = true
	d.appendActivityLocked("Activity log file unavailable: " + err.Error())
	d.mu.Unlock()
	d.publish()
}

func (d *DesktopController) recordError(action string, err error) {
	d.mu.Lock()
	d.status = action
	d.detail = err.Error()
	d.tone = "danger"
	d.appendActivityLocked(action + ": " + err.Error())
	record := d.activityRecordLocked()
	d.mu.Unlock()
	d.writeActivity(record)
	d.publish()
}

func (d *DesktopController) reportFrameworkError(err error) {
	if err != nil {
		d.recordError("Desktop runtime error", err)
	}
}

func loadActivity(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	filtered := lines[:0]
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			filtered = append(filtered, line)
		}
	}
	if len(filtered) > maxActivityLines {
		filtered = filtered[len(filtered)-maxActivityLines:]
	}
	return append([]string(nil), filtered...)
}

func removeActivityFiles(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	var result error
	for _, candidate := range []string{path, path + ".1"} {
		if err := os.Remove(candidate); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, fmt.Errorf("remove %s: %w", filepath.Base(candidate), err))
		}
	}
	return result
}

func exportActivity(path string, lines []string) error {
	content := strings.Join(lines, "\r\n")
	if content != "" {
		content += "\r\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("save activity log: %w", err)
	}
	return nil
}

func isDialogCancellation(err error) bool {
	return err != nil && err.Error() == "cancelled by user"
}

func connectionPresentation(event clientapp.Event) connectionDisplay {
	switch event.State {
	case clientapp.StateConfiguring:
		return connectionDisplay{"Configuring network", "Applying private routes, DNS, and tunnel MTU...", "warning"}
	case clientapp.StateConnected:
		detail := "Encrypted tunnel active"
		switch event.Transport {
		case tunnel.TransportHTTP3:
			detail = "HTTP/3 MASQUE - fast and resilient"
		case tunnel.TransportHTTP2:
			detail = "4-lane HTTP/2 fallback - encrypted"
		}
		if event.Lease.MTU > 0 {
			detail += fmt.Sprintf(" - MTU %d", event.Lease.MTU)
		}
		return connectionDisplay{"Connected", detail, "connected"}
	case clientapp.StateReconnecting:
		return connectionDisplay{"Reconnecting", "The network changed; restoring the secure tunnel...", "warning"}
	case clientapp.StateDisconnecting:
		return connectionDisplay{"Disconnecting", "Restoring normal network access...", "warning"}
	case clientapp.StateDisconnected:
		return connectionDisplay{"Disconnected", "Choose a profile to reconnect securely.", "offline"}
	case clientapp.StateError:
		return connectionDisplay{"Connection error", "Review Activity for details, then try again.", "danger"}
	default:
		detail := "Establishing a secure tunnel..."
		if strings.HasPrefix(event.Message, "Device:") {
			detail = strings.TrimSpace(strings.TrimPrefix(event.Message, "Device:"))
		}
		return connectionDisplay{"Connecting", detail, "warning"}
	}
}
