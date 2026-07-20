package store

import (
	"fmt"
	"os"
	"path/filepath"
)

func writeFileAtomically(path string, data []byte, mode os.FileMode) error {
	tmpPath := path + ".tmp"
	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open data directory for sync: %w", err)
	}
	defer directory.Close()
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	ok = true
	// The rename is already committed at this point. A directory fsync error
	// must not make callers roll back memory while the new file is visible.
	_ = directory.Sync()
	return nil
}
