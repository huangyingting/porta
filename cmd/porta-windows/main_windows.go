//go:build windows

package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/huangyingting/porta/internal/buildinfo"
	"github.com/huangyingting/porta/internal/clientprofile"
	"github.com/huangyingting/porta/internal/winnetwork"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"golang.org/x/sys/windows"
)

//go:embed frontend
var frontend embed.FS

//go:embed porta.ico
var portaIcon []byte

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "porta:", err)
		if len(os.Args) == 1 {
			showStartupError(err)
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
		ctx, cancel := context.WithTimeout(context.Background(), networkActionTimeout)
		defer cancel()
		return network.Down(ctx)
	}
	store, err := clientprofile.Open(filepath.Join(dataDir, "profiles.json"), clientprofile.DPAPIProtector{})
	if err != nil {
		return err
	}
	assets, err := fs.Sub(frontend, "frontend")
	if err != nil {
		return fmt.Errorf("load desktop assets: %w", err)
	}
	controller := newDesktopController(store, network, filepath.Join(dataDir, "porta.log"))
	app := application.New(application.Options{
		Name:        "Porta",
		Description: "Private network access",
		Icon:        portaIcon,
		Assets: application.AssetOptions{
			Handler: application.BundledAssetFileServer(assets),
		},
		Services: []application.Service{application.NewService(controller)},
		ErrorHandler: func(err error) {
			controller.reportFrameworkError(err)
		},
	})
	window := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:                       "porta-main",
		Title:                      "Porta " + buildinfo.Version,
		URL:                        "/",
		Width:                      920,
		Height:                     760,
		MinWidth:                   360,
		MinHeight:                  540,
		InitialPosition:            application.WindowCentered,
		BackgroundType:             application.BackgroundTypeSolid,
		BackgroundColour:           application.NewRGBA(8, 17, 31, 255),
		DevToolsEnabled:            false,
		DefaultContextMenuDisabled: true,
		Windows: application.WindowsWindow{
			Theme:                   application.Dark,
			DisableMenu:             true,
			GeneralAutofillEnabled:  false,
			PasswordAutosaveEnabled: false,
			Permissions: map[application.CoreWebView2PermissionKind]application.CoreWebView2PermissionState{
				application.CoreWebView2PermissionKindMicrophone:    application.CoreWebView2PermissionStateDeny,
				application.CoreWebView2PermissionKindCamera:        application.CoreWebView2PermissionStateDeny,
				application.CoreWebView2PermissionKindGeolocation:   application.CoreWebView2PermissionStateDeny,
				application.CoreWebView2PermissionKindNotifications: application.CoreWebView2PermissionStateDeny,
				application.CoreWebView2PermissionKindOtherSensors:  application.CoreWebView2PermissionStateDeny,
				application.CoreWebView2PermissionKindClipboardRead: application.CoreWebView2PermissionStateDeny,
			},
		},
	})

	tray := app.SystemTray.New()
	tray.SetIcon(portaIcon)
	tray.SetTooltip("Porta - Disconnected")
	menu := app.NewMenu()
	menu.Add("Open Porta").OnClick(func(*application.Context) { controller.Show() })
	connectItem := menu.Add("Connect").OnClick(func(*application.Context) { _ = controller.ToggleConnection() })
	activityItem := menu.Add("Activity").OnClick(func(*application.Context) { controller.ShowActivity() })
	restoreItem := menu.Add("Restore network").OnClick(func(*application.Context) { _ = controller.RestoreNetwork() })
	menu.AddSeparator()
	menu.Add("Quit Porta").OnClick(func(*application.Context) { controller.Quit() })
	tray.SetMenu(menu)
	tray.OnClick(controller.Show)
	tray.OnDoubleClick(controller.Show)

	controller.attach(app, window, tray, connectItem, restoreItem, activityItem)
	window.RegisterHook(events.Common.WindowClosing, func(event *application.WindowEvent) {
		if controller.CanClose() {
			return
		}
		window.Hide()
		event.Cancel()
	})
	window.RegisterHook(events.Common.WindowMinimise, func(event *application.WindowEvent) {
		window.Hide()
		event.Cancel()
	})
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		controller.publish()
	})
	return app.Run()
}

var (
	user32MessageBox = windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW")
)

func showStartupError(err error) {
	message, messageErr := windows.UTF16PtrFromString(err.Error())
	title, titleErr := windows.UTF16PtrFromString("Porta")
	if messageErr != nil || titleErr != nil {
		return
	}
	_, _, _ = user32MessageBox.Call(
		0,
		uintptr(unsafe.Pointer(message)),
		uintptr(unsafe.Pointer(title)),
		uintptr(0x10),
	)
}
