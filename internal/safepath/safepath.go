// Package safepath resolves repository-relative paths without following
// symbolic links inside the repository boundary.
package safepath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var ErrSymlink = errors.New("symbolic link in repository path")

func Existing(root, path string) (string, string, error) {
	return resolve(root, path, false)
}

func Writable(root, path string) (string, string, error) {
	return resolve(root, path, true)
}

func resolve(root, path string, allowMissing bool) (string, string, error) {
	if filepath.IsAbs(path) {
		return "", "", fmt.Errorf("absolute path is forbidden: %s", path)
	}
	clean := filepath.Clean(filepath.FromSlash(path))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("path escapes repository root: %s", path)
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", "", err
	}
	rootInfo, err := os.Lstat(absoluteRoot)
	if err != nil {
		return "", "", err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", "", fmt.Errorf("%w: %s", ErrSymlink, absoluteRoot)
	}
	current := absoluteRoot
	parts := strings.Split(clean, string(filepath.Separator))
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) && allowMissing {
			for _, remaining := range parts[index+1:] {
				current = filepath.Join(current, remaining)
			}
			break
		}
		if statErr != nil {
			return "", "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", "", fmt.Errorf("%w: %s", ErrSymlink, filepath.ToSlash(filepath.Join(parts[:index+1]...)))
		}
		if index < len(parts)-1 && !info.IsDir() {
			return "", "", fmt.Errorf("path component is not a directory: %s", filepath.ToSlash(filepath.Join(parts[:index+1]...)))
		}
	}
	return filepath.ToSlash(clean), current, nil
}
