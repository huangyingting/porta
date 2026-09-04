package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const clientDownloadPrefix = "/download/"

var clientDownloadTypes = map[string]string{
	"porta-client-linux-amd64":       "application/octet-stream",
	"porta-client-linux-arm64":       "application/octet-stream",
	"porta-client-windows-amd64.zip": "application/zip",
	"porta-android-arm64-v8a.apk":    "application/vnd.android.package-archive",
	"porta-android-armeabi-v7a.apk":  "application/vnd.android.package-archive",
	"porta-android-x86_64.apk":       "application/vnd.android.package-archive",
	"SHA256SUMS":                     "text/plain; charset=utf-8",
}

func clientDownloadHandler(next http.Handler, directory string) http.Handler {
	if directory == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, clientDownloadPrefix) {
			next.ServeHTTP(w, r)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, clientDownloadPrefix)
		contentType, allowed := clientDownloadTypes[name]
		if !allowed || r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		file, err := openDownloadFile(directory, name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		http.ServeContent(w, r, name, info.ModTime(), file)
	})
}

func openDownloadFile(directory, name string) (*os.File, error) {
	directoryFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(directoryFD)
	fileFD, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fileFD), name), nil
}
