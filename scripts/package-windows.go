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
	required := []string{"porta.exe", "porta-cli.exe", "wintun.dll"}
	for _, name := range required {
		info, err := os.Stat(filepath.Join(inputDirectory, name))
		if err != nil {
			return fmt.Errorf("validate %s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("validate %s: not a regular file", name)
		}
	}

	outputDirectory := filepath.Dir(outputPath)
	output, err := os.CreateTemp(outputDirectory, "."+filepath.Base(outputPath)+".tmp-*")
	if err != nil {
		return err
	}
	temporaryPath := output.Name()
	committed := false
	defer func() {
		_ = output.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()

	archive := zip.NewWriter(output)
	for _, name := range required {
		if err := addFile(archive, filepath.Join(inputDirectory, name), name); err != nil {
			_ = archive.Close()
			return err
		}
	}
	if err := archive.Close(); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temporaryPath, 0o644); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, outputPath); err != nil {
		return err
	}
	committed = true
	return nil
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
