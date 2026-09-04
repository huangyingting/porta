//go:build ignore

package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: package-windows OUTPUT.zip INPUT_DIRECTORY")
		os.Exit(2)
	}
	if err := packageWindows(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "package-windows:", err)
		os.Exit(1)
	}
}

func packageWindows(outputPath, inputDirectory string) error {
	output, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	archive := zip.NewWriter(output)
	for _, name := range []string{"porta.exe", "porta-cli.exe", "wintun.dll"} {
		if err := addFile(archive, filepath.Join(inputDirectory, name), name); err != nil {
			_ = archive.Close()
			_ = output.Close()
			return err
		}
	}
	if err := archive.Close(); err != nil {
		_ = output.Close()
		return err
	}
	return output.Close()
}

func addFile(archive *zip.Writer, path, name string) error {
	input, err := os.Open(path)
	if err != nil {
		return err
	}
	defer input.Close()
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.SetMode(0o755)
	header.SetModTime(time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC))
	entry, err := archive.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = io.Copy(entry, input)
	return err
}
