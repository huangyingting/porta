package main

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var getUserDefaultLocaleName = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetUserDefaultLocaleName")

func chineseWindowsLocale() bool {
	var name [85]uint16
	length, _, _ := getUserDefaultLocaleName.Call(uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)))
	return length > 1 && length <= uintptr(len(name)) &&
		strings.HasPrefix(strings.ToLower(windows.UTF16ToString(name[:length])), "zh")
}

func trayText(value string) string {
	return trayTextForLocale(value, chineseWindowsLocale())
}

func trayTextForLocale(value string, chinese bool) string {
	if !chinese {
		return value
	}
	translations := map[string]string{
		"Open Porta": "打开 Porta", "Connect": "连接", "Disconnect": "断开",
		"Activity": "连接日志", "Restore network": "恢复网络", "Quit Porta": "退出 Porta",
		"Action required": "需要处理", "Configuring network": "正在配置网络",
		"Connected": "已连接", "Connecting": "正在连接", "Connection error": "连接错误",
		"Disconnected": "已断开", "Disconnecting": "正在断开",
		"Network recovery available": "可以恢复网络", "Network recovery failed": "网络恢复失败",
		"Ready": "就绪", "Reconnecting": "正在重新连接",
		"Recovering network": "正在恢复网络", "Restoring network": "正在恢复网络",
	}
	if translated, ok := translations[value]; ok {
		return translated
	}
	return value
}
