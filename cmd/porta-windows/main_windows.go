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
	"unsafe"

	"github.com/huangyingting/porta/internal/buildinfo"
	"github.com/huangyingting/porta/internal/clientapp"
	"github.com/huangyingting/porta/internal/clientprofile"
	"github.com/huangyingting/porta/internal/tunnel"
	"github.com/huangyingting/porta/internal/winnetwork"
	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
	syswindows "golang.org/x/sys/windows"
)

const (
	trayMessage     co.WM = co.WM_APP + 1
	mainWindowStyle       = co.WS_CAPTION | co.WS_SYSMENU | co.WS_CLIPCHILDREN |
		co.WS_THICKFRAME | co.WS_VISIBLE | co.WS_MINIMIZEBOX | co.WS_MAXIMIZEBOX
)

type labelStyle struct {
	control *ui.Static
	color   win.COLORREF
	font    win.HFONT
}

type windowControl interface {
	Hwnd() win.HWND
}

type visualStyle struct {
	background      win.COLORREF
	field           win.COLORREF
	primary         win.COLORREF
	muted           win.COLORREF
	accent          win.COLORREF
	warning         win.COLORREF
	danger          win.COLORREF
	backgroundBrush win.HBRUSH
	fieldBrush      win.HBRUSH
	titleFont       win.HFONT
	headingFont     win.HFONT
	bodyFont        win.HFONT
	labelFont       win.HFONT
	monoFont        win.HFONT
}

type application struct {
	window        *ui.Main
	profiles      *ui.ComboBox
	name          *ui.Edit
	server        *ui.Edit
	transport     *ui.ComboBox
	token         *ui.Edit
	statusDot     *ui.Static
	status        *ui.Static
	statusDetail  *ui.Static
	address       *ui.Static
	duration      *ui.Static
	upload        *ui.Static
	download      *ui.Static
	logs          *ui.Edit
	connect       *ui.Button
	restore       *ui.Button
	save          *ui.Button
	remove        *ui.Button
	add           *ui.Button
	showActivity  *ui.Button
	showProfile   *ui.Button
	store         *clientprofile.Store
	network       *winnetwork.Runner
	style         *visualStyle
	labels        []labelStyle
	profileView   []windowControl
	activityView  []windowControl
	preferredSize win.SIZE
	staticColors  map[win.HWND]win.COLORREF
	items         []clientprofile.Profile
	selectedID    string
	cancel        context.CancelFunc
	running       bool
	disconnecting bool
	restoring     bool
	closing       bool
	connectedAt   time.Time
	logLines      []string
	logPath       string
	tray          win.NOTIFYICONDATA
	trayAvailable bool
	mu            sync.Mutex
}

func main() {
	runtime.LockOSThread()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "porta:", err)
		if len(os.Args) == 1 {
			_, _ = win.HWND(0).MessageBox(err.Error(), "Porta", co.MB_ICONERROR)
		}
		os.Exit(1)
	}
}

func run() error {
	if buildinfo.IsVersionRequest(os.Args[1:]) {
		fmt.Println(buildinfo.Version)
		return nil
	}
	if handled, err := winnetwork.RunHelper(context.Background(), os.Args[1:]); handled {
		return err
	}
	cleanup := len(os.Args) == 2 && os.Args[1] == "--cleanup-network"
	if len(os.Args) > 1 && !cleanup {
		return errors.New("unsupported arguments; use --version or --cleanup-network")
	}
	dataDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("locate profile directory: %w", err)
	}
	dataDir = filepath.Join(dataDir, "Porta")
	network, err := winnetwork.NewRunner(filepath.Join(dataDir, "network-state.json"))
	if err != nil {
		return err
	}
	if cleanup {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return network.Down(ctx)
	}
	store, err := clientprofile.Open(filepath.Join(dataDir, "profiles.json"), clientprofile.DPAPIProtector{})
	if err != nil {
		return err
	}
	app, err := newApplication(store, network, filepath.Join(dataDir, "porta.log"))
	if err != nil {
		return err
	}
	app.window.RunAsMain()
	app.style.close()
	return nil
}

func newApplication(store *clientprofile.Store, network *winnetwork.Runner, logPath string) (*application, error) {
	style, err := newVisualStyle()
	if err != nil {
		return nil, err
	}
	minimumWidth, minimumHeight := minimumClientSize()
	preferredWidth, preferredHeight := preferredClientSize()
	logHeight := minimumHeight - ui.DpiY(245)
	window := ui.NewMain(
		ui.OptsMain().
			Title("Porta "+buildinfo.Version).
			Size(minimumWidth, minimumHeight).
			ClassIconId(101).
			ClassBrush(style.backgroundBrush).
			Style(mainWindowStyle),
	)
	app := &application{
		window: window, store: store, network: network, logPath: logPath, style: style,
		preferredSize: win.SIZE{Cx: int32(preferredWidth), Cy: int32(preferredHeight)},
		staticColors:  make(map[win.HWND]win.COLORREF),
	}
	addLabel := func(text string, x, y, width, height int, font win.HFONT, color win.COLORREF, layout ...ui.LAY) *ui.Static {
		options := ui.OptsStatic().Text(text).Position(ui.Dpi(x, y)).Size(ui.Dpi(width, height))
		if len(layout) > 0 {
			options.Layout(layout[0])
		}
		label := ui.NewStatic(window, options)
		app.labels = append(app.labels, labelStyle{control: label, color: color, font: font})
		return label
	}

	addLabel("Porta", 20, 8, 160, 32, style.titleFont, style.primary)
	addLabel("Private network access", 20, 38, 260, 18, style.bodyFont, style.muted)
	addLabel("v"+buildinfo.Version, 390, 16, 70, 22, style.labelFont, style.accent, ui.LAY_MOVE_HOLD)

	app.statusDot = addLabel("●", 20, 60, 20, 26, style.headingFont, style.muted)
	app.status = addLabel("Disconnected", 46, 58, 280, 26, style.headingFont, style.primary)
	app.statusDetail = addLabel("Choose a profile or add one to connect securely.", 46, 84, 414, 20, style.bodyFont, style.muted, ui.LAY_RESIZE_HOLD)

	app.profiles = ui.NewComboBox(window, ui.OptsComboBox().
		Position(ui.Dpi(20, 108)).Width(ui.DpiX(280)).Texts("New profile").Select(0).
		Layout(ui.LAY_RESIZE_HOLD))
	app.add = ui.NewButton(window, ui.OptsButton().Text("Add profile").
		Position(ui.Dpi(310, 107)).Width(ui.DpiX(70)).Layout(ui.LAY_MOVE_HOLD))
	app.remove = ui.NewButton(window, ui.OptsButton().Text("Delete").
		Position(ui.Dpi(390, 107)).Width(ui.DpiX(70)).Layout(ui.LAY_MOVE_HOLD))
	app.profileView = append(app.profileView, app.profiles, app.add, app.remove)

	nameLabel := addLabel("PROFILE NAME", 20, 140, 150, 16, style.labelFont, style.muted)
	app.name = ui.NewEdit(window, ui.OptsEdit().
		Position(ui.Dpi(20, 156)).Width(ui.DpiX(205)).Height(ui.DpiY(24)))
	transportLabel := addLabel("TRANSPORT", 235, 140, 150, 16, style.labelFont, style.muted)
	app.transport = ui.NewComboBox(window, ui.OptsComboBox().
		Position(ui.Dpi(235, 156)).Width(ui.DpiX(225)).
		Texts("Automatic (recommended)", "HTTP/3 only", "HTTP/2 only").Select(0).
		Layout(ui.LAY_RESIZE_HOLD))

	serverLabel := addLabel("GATEWAY URL", 20, 186, 150, 16, style.labelFont, style.muted)
	app.server = ui.NewEdit(window, ui.OptsEdit().
		Position(ui.Dpi(20, 202)).Width(ui.DpiX(440)).Height(ui.DpiY(24)).
		Layout(ui.LAY_RESIZE_HOLD))
	tokenLabel := addLabel("CLIENT TOKEN · DPAPI PROTECTED", 20, 232, 240, 16, style.labelFont, style.muted)
	app.token = ui.NewEdit(window, ui.OptsEdit().
		Position(ui.Dpi(20, 248)).Width(ui.DpiX(440)).Height(ui.DpiY(24)).
		CtrlStyle(co.ES_LEFT|co.ES_AUTOHSCROLL|co.ES_PASSWORD).
		Layout(ui.LAY_RESIZE_HOLD))

	app.save = ui.NewButton(window, ui.OptsButton().Text("Save profile").
		Position(ui.Dpi(20, 274)).Width(ui.DpiX(90)).Layout(ui.LAY_HOLD_MOVE))
	app.restore = ui.NewButton(window, ui.OptsButton().Text("Restore network").
		Position(ui.Dpi(120, 274)).Width(ui.DpiX(105)).Layout(ui.LAY_HOLD_MOVE))
	app.showActivity = ui.NewButton(window, ui.OptsButton().Text("Activity").
		Position(ui.Dpi(235, 274)).Width(ui.DpiX(80)).Layout(ui.LAY_HOLD_MOVE))
	app.connect = ui.NewButton(window, ui.OptsButton().Text("Connect").
		Position(ui.Dpi(345, 274)).Width(ui.DpiX(115)).
		Layout(ui.LAY_MOVE_MOVE).
		CtrlStyle(co.BS_DEFPUSHBUTTON))
	app.profileView = append(app.profileView,
		nameLabel, app.name, transportLabel, app.transport, serverLabel, app.server,
		tokenLabel, app.token, app.save, app.restore, app.showActivity,
	)

	activityTitle := addLabel("CONNECTION ACTIVITY", 20, 112, 220, 20, style.labelFont, style.muted)
	app.showProfile = ui.NewButton(window, ui.OptsButton().Text("Profile").
		Position(ui.Dpi(370, 106)).Width(ui.DpiX(90)).Layout(ui.LAY_MOVE_HOLD))
	addressLabel := addLabel("ADDRESS", 20, 146, 95, 16, style.labelFont, style.muted)
	durationLabel := addLabel("DURATION", 130, 146, 95, 16, style.labelFont, style.muted)
	uploadLabel := addLabel("SENT", 240, 146, 95, 16, style.labelFont, style.muted)
	downloadLabel := addLabel("RECEIVED", 350, 146, 110, 16, style.labelFont, style.muted)
	app.address = addLabel("—", 20, 164, 100, 22, style.bodyFont, style.primary)
	app.duration = addLabel("—", 130, 164, 100, 22, style.bodyFont, style.primary)
	app.upload = addLabel("0 B", 240, 164, 100, 22, style.bodyFont, style.primary)
	app.download = addLabel("0 B", 350, 164, 110, 22, style.bodyFont, style.primary)
	app.logs = ui.NewEdit(window, ui.OptsEdit().
		Position(ui.Dpi(20, 196)).Width(ui.DpiX(440)).Height(logHeight).
		Layout(ui.LAY_RESIZE_RESIZE).
		CtrlStyle(co.ES_LEFT|co.ES_MULTILINE|co.ES_AUTOVSCROLL|co.ES_READONLY).
		WndStyle(co.WS_CHILD|co.WS_VISIBLE|co.WS_VSCROLL))
	app.activityView = append(app.activityView,
		activityTitle, app.showProfile, addressLabel, durationLabel, uploadLabel, downloadLabel,
		app.address, app.duration, app.upload, app.download, app.logs,
	)

	app.profiles.On().CbnSelChange(app.selectProfile)
	app.add.On().BnClicked(app.newProfile)
	app.save.On().BnClicked(func() { app.saveProfile() })
	app.remove.On().BnClicked(app.deleteProfile)
	app.showActivity.On().BnClicked(func() { app.setActivityView(true) })
	app.showProfile.On().BnClicked(func() { app.setActivityView(false) })
	app.connect.On().BnClicked(app.toggleConnection)
	app.restore.On().BnClicked(func() {
		answer, _ := app.window.Hwnd().MessageBox(
			"Restore normal connectivity and remove Porta's retained network protection?",
			"Porta", co.MB_YESNO|co.MB_ICONQUESTION,
		)
		if answer == co.ID_YES {
			app.restoreNetwork()
		}
	})
	window.On().WmCreate(func(ui.WmCreate) int {
		app.applyVisualStyle()
		app.resizeAndCenterInWorkArea()
		app.addTray()
		app.setActivityView(false)
		profiles := app.store.List()
		if len(profiles) == 0 {
			app.reloadProfiles("")
			app.newProfile()
		} else {
			app.reloadProfiles(profiles[0].ID)
		}
		app.restore.Hwnd().EnableWindow(network.NeedsCleanup())
		if network.NeedsCleanup() {
			app.setConnectionStatus("Network recovery available", "Reconnect to resume, or restore normal connectivity.", style.warning)
			app.appendLog("Reconnect to resume, or Restore network to remove retained settings.")
		}
		return 0
	})
	window.On().WmEraseBkgnd(func(event ui.WmEraseBkgnd) int {
		rect, err := app.window.Hwnd().GetClientRect()
		if err == nil {
			_ = event.Hdc().FillRect(&rect, style.backgroundBrush)
		}
		return 1
	})
	window.On().WmCtlColorStatic(app.colorStatic)
	window.On().WmCtlColorEdit(func(event ui.WmCtlColor) win.HBRUSH {
		app.colorControl(event, style.primary, style.field)
		return style.fieldBrush
	})
	window.On().WmCtlColorListBox(func(event ui.WmCtlColor) win.HBRUSH {
		app.colorControl(event, style.primary, style.field)
		return style.fieldBrush
	})
	window.On().WmCtlColorBtn(func(event ui.WmCtlColor) win.HBRUSH {
		app.colorControl(event, style.primary, style.background)
		return style.backgroundBrush
	})
	window.On().WmGetMinMaxInfo(func(event ui.WmGetMinMaxInfo) {
		event.Info().PtMinTrackSize = minimumWindowTrackSize()
	})
	window.On().Wm(trayMessage, app.trayEvent)
	window.On().WmClose(app.close)
	window.On().WmDestroy(func() { _ = win.Shell_NotifyIcon(co.NIM_DELETE, &app.tray) })
	return app, nil
}

func minimumClientSize() (int, int) {
	return ui.DpiX(480), ui.DpiY(305)
}

func preferredClientSize() (int, int) {
	minimumWidth, minimumHeight := minimumClientSize()
	width := ui.DpiX(620)
	height := ui.DpiY(520)
	var workArea win.RECT
	if err := win.SystemParametersInfo(co.SPI_GETWORKAREA, 0, unsafe.Pointer(&workArea), 0); err == nil {
		frame := win.RECT{Right: int32(width), Bottom: int32(height)}
		if err := win.AdjustWindowRectEx(&frame, mainWindowStyle, false, 0); err == nil {
			nonClientWidth := int(frame.Right-frame.Left) - width
			nonClientHeight := int(frame.Bottom-frame.Top) - height
			availableClientWidth := int(workArea.Right-workArea.Left) - ui.DpiX(16) - nonClientWidth
			availableClientHeight := int(workArea.Bottom-workArea.Top) - ui.DpiY(16) - nonClientHeight
			if availableClientWidth < width {
				width = availableClientWidth
			}
			if availableClientHeight < height {
				height = availableClientHeight
			}
		}
	}
	if width < minimumWidth {
		width = minimumWidth
	}
	if height < minimumHeight {
		height = minimumHeight
	}
	return width, height
}

func minimumWindowTrackSize() win.POINT {
	width, height := minimumClientSize()
	rect := win.RECT{Right: int32(width), Bottom: int32(height)}
	if err := win.AdjustWindowRectEx(&rect, mainWindowStyle, false, 0); err != nil {
		return win.POINT{X: rect.Right, Y: rect.Bottom}
	}
	return win.POINT{X: rect.Right - rect.Left, Y: rect.Bottom - rect.Top}
}

func newVisualStyle() (*visualStyle, error) {
	style := &visualStyle{
		background: win.RGB(8, 17, 31),
		field:      win.RGB(11, 23, 40),
		primary:    win.RGB(242, 247, 252),
		muted:      win.RGB(148, 163, 184),
		accent:     win.RGB(110, 231, 183),
		warning:    win.RGB(250, 204, 21),
		danger:     win.RGB(251, 113, 133),
	}
	var err error
	if style.backgroundBrush, err = newSolidBrush(style.background); err != nil {
		return nil, fmt.Errorf("create window background: %w", err)
	}
	if style.fieldBrush, err = newSolidBrush(style.field); err != nil {
		style.close()
		return nil, fmt.Errorf("create field background: %w", err)
	}
	fonts := []struct {
		target *win.HFONT
		size   int
		weight co.FW
		face   string
	}{
		{&style.titleFont, 28, co.FW_SEMIBOLD, "Segoe UI"},
		{&style.headingFont, 18, co.FW_SEMIBOLD, "Segoe UI"},
		{&style.bodyFont, 14, co.FW_NORMAL, "Segoe UI"},
		{&style.labelFont, 11, co.FW_SEMIBOLD, "Segoe UI"},
		{&style.monoFont, 12, co.FW_NORMAL, "Cascadia Mono"},
	}
	for _, font := range fonts {
		*font.target, err = newFont(font.size, font.weight, font.face)
		if err != nil {
			style.close()
			return nil, fmt.Errorf("create %s font: %w", font.face, err)
		}
	}
	return style, nil
}

func newSolidBrush(color win.COLORREF) (win.HBRUSH, error) {
	return win.CreateBrushIndirect(&win.LOGBRUSH{Style: co.BRS_SOLID, Color: color})
}

func newFont(size int, weight co.FW, face string) (win.HFONT, error) {
	font := win.LOGFONT{
		Height:        int32(ui.DpiY(-size)),
		Weight:        weight,
		CharSet:       co.CHARSET_DEFAULT,
		OutPrecision:  co.OUT_PRECIS_DEFAULT,
		ClipPrecision: co.CLIP_PRECIS_DEFAULT,
		Quality:       co.QUALITY_CLEARTYPE,
	}
	font.SetPitch(co.PITCH_VARIABLE)
	font.SetFamily(co.FF_SWISS)
	font.SetFaceName(face)
	return win.CreateFontIndirect(&font)
}

func (s *visualStyle) close() {
	for _, font := range []win.HFONT{s.titleFont, s.headingFont, s.bodyFont, s.labelFont, s.monoFont} {
		if font != 0 {
			_ = font.DeleteObject()
		}
	}
	for _, brush := range []win.HBRUSH{s.fieldBrush, s.backgroundBrush} {
		if brush != 0 {
			_ = brush.DeleteObject()
		}
	}
}

func (a *application) applyVisualStyle() {
	_ = a.window.Hwnd().DwmSetWindowAttribute(win.DwmAttrUseImmersiveDarkMode(true))
	_ = a.window.Hwnd().DwmSetWindowAttribute(win.DwmAttrCaptionColor(a.style.background))
	_ = a.window.Hwnd().DwmSetWindowAttribute(win.DwmAttrTextColor(a.style.primary))

	for _, label := range a.labels {
		label.control.Hwnd().SendMessage(co.WM_SETFONT, win.WPARAM(label.font), win.LPARAM(1))
		a.staticColors[label.control.Hwnd()] = label.color
	}
	for _, control := range []win.HWND{
		a.profiles.Hwnd(), a.transport.Hwnd(), a.name.Hwnd(), a.server.Hwnd(), a.token.Hwnd(),
		a.save.Hwnd(), a.restore.Hwnd(), a.connect.Hwnd(), a.remove.Hwnd(), a.add.Hwnd(),
		a.showActivity.Hwnd(), a.showProfile.Hwnd(),
	} {
		control.SendMessage(co.WM_SETFONT, win.WPARAM(a.style.bodyFont), win.LPARAM(1))
		setDarkControlTheme(control)
	}
	a.logs.Hwnd().SendMessage(co.WM_SETFONT, win.WPARAM(a.style.monoFont), win.LPARAM(1))
	setDarkControlTheme(a.logs.Hwnd())
}

func (a *application) resizeAndCenterInWorkArea() {
	var workArea win.RECT
	if err := win.SystemParametersInfo(co.SPI_GETWORKAREA, 0, unsafe.Pointer(&workArea), 0); err != nil {
		return
	}
	windowRect := win.RECT{Right: a.preferredSize.Cx, Bottom: a.preferredSize.Cy}
	if err := win.AdjustWindowRectEx(&windowRect, mainWindowStyle, false, 0); err != nil {
		return
	}
	width := windowRect.Right - windowRect.Left
	height := windowRect.Bottom - windowRect.Top
	position := win.POINT{
		X: workArea.Left + (workArea.Right-workArea.Left-width)/2,
		Y: workArea.Top + (workArea.Bottom-workArea.Top-height)/2,
	}
	_ = a.window.Hwnd().SetWindowPos(
		0, position, win.SIZE{Cx: width, Cy: height}, co.SWP_NOZORDER|co.SWP_NOACTIVATE,
	)
}

func (a *application) setActivityView(show bool) {
	profileState, activityState := co.SW_SHOW, co.SW_HIDE
	if show {
		profileState, activityState = co.SW_HIDE, co.SW_SHOW
	}
	for _, control := range a.profileView {
		control.Hwnd().ShowWindow(profileState)
	}
	for _, control := range a.activityView {
		control.Hwnd().ShowWindow(activityState)
	}
	if show {
		a.logs.SetSelection(-1, -1)
		a.showProfile.Hwnd().SetFocus()
	} else {
		a.profiles.Hwnd().SetFocus()
	}
}

func (a *application) colorStatic(event ui.WmCtlColor) win.HBRUSH {
	if event.HwndControl() == a.logs.Hwnd() {
		a.colorControl(event, a.style.primary, a.style.field)
		return a.style.fieldBrush
	}
	color := a.style.primary
	if configured, ok := a.staticColors[event.HwndControl()]; ok {
		color = configured
	}
	a.colorControl(event, color, a.style.background)
	return a.style.backgroundBrush
}

func (a *application) colorControl(event ui.WmCtlColor, text, background win.COLORREF) {
	_, _ = event.Hdc().SetTextColor(text)
	_, _ = event.Hdc().SetBkColor(background)
	_, _ = event.Hdc().SetBkMode(co.BKMODE_OPAQUE)
}

func (a *application) setConnectionStatus(title, detail string, dotColor win.COLORREF) {
	setText(a.status, title)
	setText(a.statusDetail, detail)
	a.staticColors[a.statusDot.Hwnd()] = dotColor
	_ = a.statusDot.Hwnd().InvalidateRect(nil, true)
}

func setDarkControlTheme(control win.HWND) {
	name, err := syswindows.UTF16PtrFromString("DarkMode_Explorer")
	if err != nil {
		return
	}
	_, _, _ = setWindowTheme.Call(uintptr(control), uintptr(unsafe.Pointer(name)), 0)
}

var setWindowTheme = syswindows.NewLazySystemDLL("uxtheme.dll").NewProc("SetWindowTheme")

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
	a.token.SetText("")
	a.transport.SelectIndex(transportIndex(profile.Transport))
	if !a.running && !a.restoring {
		a.setConnectionStatus("Ready", profile.Name+" · "+profile.ServerURL, a.style.muted)
	}
	a.appendLog("Selected profile " + profile.Name)
}

func (a *application) newProfile() {
	if a.running || a.restoring {
		return
	}
	a.selectedID = ""
	a.profiles.SelectIndex(0)
	a.name.SetText("")
	a.server.SetText("https://")
	a.transport.SelectIndex(0)
	a.token.SetText("")
	a.setConnectionStatus("Add a profile", "Enter the gateway and client token to begin.", a.style.muted)
	a.name.Hwnd().SetFocus()
}

func (a *application) profileFromFields() clientprofile.Profile {
	transport := selectedTransport(a.transport.SelectedIndex())
	var original clientprofile.Profile
	for _, profile := range a.items {
		if profile.ID == a.selectedID {
			original = profile
			break
		}
	}
	return profileWithFields(original, clientprofile.Profile{
		ID:        a.selectedID,
		Name:      strings.TrimSpace(a.name.Text()),
		ServerURL: strings.TrimSpace(a.server.Text()),
		Transport: transport,
	})
}

func (a *application) saveProfile() bool {
	if a.running || a.restoring {
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
	if a.running || a.restoring || a.selectedID == "" {
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
	if a.restoring {
		a.mu.Unlock()
		return
	}
	if a.running {
		cancel := a.cancel
		a.disconnecting = true
		a.mu.Unlock()
		a.setConnectionStatus("Disconnecting", "Restoring normal network access…", a.style.warning)
		a.connect.SetText("Disconnecting…")
		a.connect.Hwnd().EnableWindow(false)
		a.updateTray("Disconnecting")
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
	a.disconnecting = false
	a.cancel = cancel
	a.mu.Unlock()
	a.setEditing(false)
	a.connect.SetText("Cancel")
	a.setConnectionStatus("Connecting", "Establishing a secure tunnel…", a.style.warning)
	setText(a.address, "—")
	setText(a.duration, "—")
	setText(a.upload, "0 B")
	setText(a.download, "0 B")
	a.appendLog("Connecting to " + profile.ServerURL)
	go func() {
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
			Network:           a.network,
		}, a.handleEvent)
		a.window.UiThread(func() {
			a.mu.Lock()
			a.running = false
			a.disconnecting = false
			a.cancel = nil
			closing := a.closing
			a.mu.Unlock()
			a.setEditing(true)
			a.connect.SetText("Connect")
			a.connect.Hwnd().EnableWindow(true)
			if err != nil && err != context.Canceled {
				a.appendLog("Error: " + err.Error())
				a.setConnectionStatus("Connection error", "Review the activity log, then try again.", a.style.danger)
				a.updateTray("Error")
			} else {
				a.setConnectionStatus("Disconnected", "Choose a profile to reconnect securely.", a.style.muted)
				a.updateTray("Disconnected")
			}
			setText(a.address, "—")
			if closing && canExitAfterDisconnect(err, a.network.NeedsCleanup()) {
				a.window.Hwnd().DestroyWindow()
			} else if closing {
				a.closing = false
				a.window.Hwnd().ShowWindow(co.SW_RESTORE)
			}
		})
	}()
}

func (a *application) handleEvent(event clientapp.Event) {
	a.window.UiThread(func() {
		if a.disconnecting && event.State != clientapp.StateError && event.State != clientapp.StateDisconnected {
			return
		}
		title, detail, color := a.connectionPresentation(event)
		a.setConnectionStatus(title, detail, color)
		a.updateTray(title)
		if event.State == clientapp.StateConnected {
			a.connectedAt = event.ConnectedAt
			a.connect.SetText("Disconnect")
		}
		if event.Lease.Address.IsValid() {
			setText(a.address, event.Lease.Address.String())
		}
		if !event.ConnectedAt.IsZero() {
			setText(a.duration, formatDuration(time.Since(event.ConnectedAt)))
		}
		setText(a.upload, formatBytes(event.BytesUploaded))
		setText(a.download, formatBytes(event.BytesDownloaded))
		if event.State != clientapp.StateConnected || event.Message != "Connected" {
			a.appendLog(event.Message)
		}
	})
}

func (a *application) connectionPresentation(event clientapp.Event) (string, string, win.COLORREF) {
	switch event.State {
	case clientapp.StateConfiguring:
		return "Configuring network", "Applying private routes, DNS, and tunnel MTU…", a.style.warning
	case clientapp.StateConnected:
		detail := "Encrypted tunnel active"
		switch event.Transport {
		case tunnel.TransportHTTP3:
			detail = "HTTP/3 MASQUE · Fast and resilient"
		case tunnel.TransportHTTP2:
			detail = "4-lane HTTP/2 fallback · Encrypted"
		}
		if event.Lease.MTU > 0 {
			detail += fmt.Sprintf(" · MTU %d", event.Lease.MTU)
		}
		return "Connected", detail, a.style.accent
	case clientapp.StateReconnecting:
		return "Reconnecting", "The network changed; restoring the secure tunnel…", a.style.warning
	case clientapp.StateDisconnecting:
		return "Disconnecting", "Restoring normal network access…", a.style.warning
	case clientapp.StateDisconnected:
		return "Disconnected", "Choose a profile to reconnect securely.", a.style.muted
	case clientapp.StateError:
		return "Connection error", "Review the activity log, then try again.", a.style.danger
	default:
		detail := "Establishing a secure tunnel…"
		if strings.HasPrefix(event.Message, "Device:") {
			detail = strings.TrimPrefix(event.Message, "Device: ")
		}
		return "Connecting", detail, a.style.warning
	}
}

func (a *application) setEditing(enabled bool) {
	a.profiles.Hwnd().EnableWindow(enabled)
	a.name.Hwnd().EnableWindow(enabled)
	a.server.Hwnd().EnableWindow(enabled)
	a.transport.Hwnd().EnableWindow(enabled)
	a.token.Hwnd().EnableWindow(enabled)
	a.save.Hwnd().EnableWindow(enabled)
	a.remove.Hwnd().EnableWindow(enabled)
	a.add.Hwnd().EnableWindow(enabled)
	a.restore.Hwnd().EnableWindow(enabled && a.network.NeedsCleanup())
}

func (a *application) restoreNetwork() {
	a.mu.Lock()
	if a.running || a.restoring {
		a.mu.Unlock()
		return
	}
	a.restoring = true
	a.mu.Unlock()
	a.setEditing(false)
	a.connect.Hwnd().EnableWindow(false)
	a.setConnectionStatus("Restoring network", "Removing retained routes and leak protection…", a.style.warning)
	a.updateTray("Restoring network")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err := a.network.Down(ctx)
		cancel()
		a.window.UiThread(func() {
			a.mu.Lock()
			a.restoring = false
			closing := a.closing
			if err != nil {
				a.closing = false
			}
			a.mu.Unlock()
			a.setEditing(true)
			a.connect.Hwnd().EnableWindow(true)
			if closing && errors.Is(err, winnetwork.ErrStateInUse) {
				a.window.Hwnd().DestroyWindow()
				return
			}
			if err != nil {
				a.setConnectionStatus("Network recovery failed", "Review the activity log and try Restore network again.", a.style.danger)
				a.updateTray("Network recovery failed")
				a.window.Hwnd().ShowWindow(co.SW_RESTORE)
				a.showError(err)
				return
			}
			a.setConnectionStatus("Disconnected", "Normal network access has been restored.", a.style.muted)
			a.updateTray("Disconnected")
			a.appendLog("Restored network and removed retained protection.")
			if closing {
				a.window.Hwnd().DestroyWindow()
			}
		})
	}()
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
	a.setConnectionStatus("Action failed", "Review the activity log for details.", a.style.danger)
	_, _ = a.window.Hwnd().MessageBox(err.Error(), "Porta", co.MB_ICONERROR)
}

func (a *application) close() {
	a.mu.Lock()
	if !a.closing && a.trayAvailable {
		a.mu.Unlock()
		a.window.Hwnd().ShowWindow(co.SW_HIDE)
		return
	}
	if a.restoring {
		a.closing = true
		a.mu.Unlock()
		return
	}
	if !a.running {
		a.closing = true
		a.mu.Unlock()
		if a.network.NeedsCleanup() {
			a.restoreNetwork()
		} else {
			a.window.Hwnd().DestroyWindow()
		}
		return
	}
	a.closing = true
	a.disconnecting = true
	cancel := a.cancel
	a.mu.Unlock()
	a.setConnectionStatus("Disconnecting", "Restoring normal network access…", a.style.warning)
	a.connect.Hwnd().EnableWindow(false)
	a.updateTray("Disconnecting")
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
	a.trayAvailable = win.Shell_NotifyIcon(co.NIM_ADD, &a.tray) == nil
}

func (a *application) updateTray(status string) {
	if !a.trayAvailable {
		return
	}
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
