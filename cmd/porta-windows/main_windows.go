//go:build windows

package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	if len(os.Args) == 3 && os.Args[1] == "--restart-after" {
		return restartAfter(os.Args[2])
	}
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
	dataDir, err := windows.KnownFolderPath(windows.FOLDERID_RoamingAppData, 0)
	if err != nil {
		return fmt.Errorf("locate profile directory: %w", err)
	}
	dataDir = filepath.Join(dataDir, "Porta")
	statePath, startupErr := winnetwork.DefaultStatePath()
	if startupErr != nil {
		statePath, err = winnetwork.CurrentStatePath()
		if err != nil {
			return err
		}
	}
	var network *winnetwork.Runner
	if startupErr == nil {
		network, startupErr = winnetwork.NewRunner(statePath)
	}
	if cleanup {
		if startupErr != nil {
			return startupErr
		}
		ctx, cancel := context.WithTimeout(context.Background(), networkActionTimeout)
		defer cancel()
		return network.Down(ctx)
	}
	root, err := winnetwork.PrepareProtectedDirectory(filepath.Dir(statePath))
	if err != nil {
		return fmt.Errorf("initialize protected activity log: %w", err)
	}
	defer root.Close()
	logDir := filepath.Join(filepath.Dir(statePath), "logs")
	logPin, err := winnetwork.PrepareProtectedDirectory(logDir)
	if err != nil {
		return fmt.Errorf("initialize protected activity log: %w", err)
	}
	defer logPin.Close()
	store, err := clientprofile.Open(filepath.Join(dataDir, "profiles.json"), clientprofile.DPAPIProtector{})
	if err != nil {
		return err
	}
	assets, err := fs.Sub(frontend, "frontend")
	if err != nil {
		return fmt.Errorf("load desktop assets: %w", err)
	}
	controller := newDesktopController(store, network, filepath.Join(logDir, "porta.log"))
	if startupErr != nil {
		controller.blockStartup(startupErr)
	}
	app := application.New(application.Options{
		Name:        "Porta",
		Description: "Private network access",
		Icon:        portaIcon,
		Assets: application.AssetOptions{
			Handler: application.BundledAssetFileServer(assets),
		},
		Services: []application.Service{application.NewService(controller)},
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: "dev.porta.windows",
			OnSecondInstanceLaunch: func(application.SecondInstanceData) {
				controller.Reactivate()
			},
		},
		ErrorHandler: func(err error) {
			controller.reportFrameworkError(err)
		},
	})
	window := app.Window.NewWithOptions(mainWindowOptions())

	tray := app.SystemTray.New()
	tray.SetIcon(portaIcon)
	tray.SetTooltip("Porta - " + trayText("Disconnected"))
	menu := app.NewMenu()
	menu.Add(trayText("Open Porta")).OnClick(func(*application.Context) { controller.Show() })
	connectItem := menu.Add(trayText("Connect")).OnClick(func(*application.Context) {
		if err := controller.ToggleConnection(); err != nil {
			controller.recordError("Connection action failed", err)
			controller.Show()
		}
	})
	activityItem := menu.Add(trayText("Activity")).OnClick(func(*application.Context) { controller.ShowActivity() })
	restoreItem := menu.Add(trayText("Restore network")).OnClick(func(*application.Context) {
		if err := controller.RestoreNetwork(); err != nil {
			controller.recordError("Network recovery failed", err)
			controller.Show()
		}
	})
	menu.AddSeparator()
	menu.Add(trayText("Quit Porta")).OnClick(func(*application.Context) { controller.Quit() })
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

func mainWindowOptions() application.WebviewWindowOptions {
	return application.WebviewWindowOptions{
		Name:                       "porta-main",
		Title:                      "Porta " + buildinfo.Version,
		URL:                        "/",
		Width:                      440,
		Height:                     600,
		MinWidth:                   440,
		MinHeight:                  520,
		DisableResize:              true,
		InitialPosition:            application.WindowCentered,
		BackgroundType:             application.BackgroundTypeSolid,
		BackgroundColour:           application.NewRGBA(8, 17, 31, 255),
		DevToolsEnabled:            false,
		DefaultContextMenuDisabled: true,
		MinimiseButtonState:        application.ButtonHidden,
		MaximiseButtonState:        application.ButtonHidden,
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
	}
}

func restartAfter(value string) error {
	pid, err := strconv.ParseUint(value, 10, 32)
	if err != nil || pid == 0 {
		return errors.New("invalid restart parent process")
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err == nil {
		event, waitErr := windows.WaitForSingleObject(handle, 30_000)
		_ = windows.CloseHandle(handle)
		if waitErr != nil {
			return fmt.Errorf("wait for previous instance: %w", waitErr)
		}
		if event != windows.WAIT_OBJECT_0 {
			return errors.New("previous instance did not exit within 30 seconds")
		}
	} else if !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return fmt.Errorf("open previous instance: %w", err)
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	if err := startDetachedProcess(executable); err != nil {
		return fmt.Errorf("start replacement instance: %w", err)
	}
	return nil
}

func startDetachedProcess(name string, arguments ...string) error {
	command := exec.Command(name, arguments...)
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
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
