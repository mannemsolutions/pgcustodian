package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func ResolveHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	return filepath.Clean(path)
}

func MakeTree(folderPath string) error {
	return os.MkdirAll(ResolveHome(folderPath), os.ModePerm)
}

func AbsolutePath(relativePath string) (absPath string, err error) {
	absPath = ResolveHome(relativePath)
	if absPath, err = filepath.EvalSymlinks(absPath); err != nil {
		return "", fmt.Errorf("failed to resolve symlink %s: %w", absPath, err)
	} else if absPath, err = filepath.Abs(absPath); err != nil {
		return "", fmt.Errorf("failed to get absolute path for %s: %w", absPath, err)
	} else {
		return absPath, nil
	}

}
