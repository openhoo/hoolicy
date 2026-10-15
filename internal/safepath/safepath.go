// Package safepath resolves repository-relative paths without following
// symbolic links inside the repository boundary.
package safepath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var ErrSymlink = errors.New("symbolic link in repository path")

// GitMetadataPath identifies reserved Git components, including portable
// case and trailing-dot aliases and Windows alternate data streams.
func GitMetadataPath(path string) bool {
	for _, component := range strings.Split(path, "/") {
		component = strings.SplitN(component, ":", 2)[0]
		if strings.EqualFold(strings.TrimRight(component, " ."), ".git") {
			return true
		}
	}
	return false
}

func Existing(root, path string) (string, string, error) {
	return resolve(root, path, false)
}

func Writable(root, path string) (string, string, error) {
	return resolve(root, path, true)
}

// Relative validates and cleans a repository-relative path without touching
// the filesystem. It is useful for immutable snapshots whose source tree may
// no longer exist in the live worktree.
func Relative(path string) (string, error) {
	if filepath.IsAbs(path) || strings.HasPrefix(path, "/") || strings.Contains(path, "\\") || hasWindowsVolume(path) {
		return "", fmt.Errorf("absolute path is forbidden: %s", path)
	}
	clean := filepath.Clean(filepath.FromSlash(path))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes repository root: %s", path)
	}
	return filepath.ToSlash(clean), nil
}

func resolve(root, path string, allowMissing bool) (string, string, error) {
	clean, err := Relative(path)
	if err != nil {
		return "", "", err
	}
	current, err := verifiedRoot(root)
	if err != nil {
		return "", "", err
	}
	parts := strings.Split(filepath.FromSlash(clean), string(filepath.Separator))
	for index, part := range parts {
		current = filepath.Join(current, part)
		_, statErr := component(current, parts, index)
		if errors.Is(statErr, os.ErrNotExist) && allowMissing {
			for _, remaining := range parts[index+1:] {
				current = filepath.Join(current, remaining)
			}
			break
		}
		if statErr != nil {
			return "", "", statErr
		}
	}
	return clean, current, nil
}

// Resolver resolves many existing paths below one root with the same checks
// as Existing. Each directory component is inspected once and its result is
// reused, which matters on file systems where every metadata call is a
// network or virtual-machine round trip. A Resolver describes one snapshot
// pass; create a new one instead of reusing it after the tree may have changed.
// It is safe for concurrent use.
type Resolver struct {
	root        string
	rootOnce    sync.Once
	rootPath    string
	rootErr     error
	mutex       sync.Mutex
	directories map[string]*directoryCheck
}

type directoryCheck struct {
	once sync.Once
	err  error
}

func NewResolver(root string) *Resolver {
	return &Resolver{root: root, directories: make(map[string]*directoryCheck)}
}

// Existing resolves path like the package-level Existing function and also
// returns the Lstat information of the final component.
func (r *Resolver) Existing(path string) (string, string, os.FileInfo, error) {
	clean, err := Relative(path)
	if err != nil {
		return "", "", nil, err
	}
	r.rootOnce.Do(func() { r.rootPath, r.rootErr = verifiedRoot(r.root) })
	if r.rootErr != nil {
		return "", "", nil, r.rootErr
	}
	parts := strings.Split(filepath.FromSlash(clean), string(filepath.Separator))
	for index := range len(parts) - 1 {
		if err := r.directory(parts, index); err != nil {
			return "", "", nil, err
		}
	}
	absolute := filepath.Join(append([]string{r.rootPath}, parts...)...)
	info, err := component(absolute, parts, len(parts)-1)
	if err != nil {
		return "", "", nil, err
	}
	return clean, absolute, info, nil
}

func (r *Resolver) directory(parts []string, index int) error {
	key := filepath.Join(parts[:index+1]...)
	r.mutex.Lock()
	check := r.directories[key]
	if check == nil {
		check = &directoryCheck{}
		r.directories[key] = check
	}
	r.mutex.Unlock()
	check.once.Do(func() {
		_, check.err = component(filepath.Join(r.rootPath, key), parts, index)
	})
	return check.err
}

func verifiedRoot(root string) (string, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	rootInfo, err := os.Lstat(absoluteRoot)
	if err != nil {
		return "", err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: %s", ErrSymlink, absoluteRoot)
	}
	return absoluteRoot, nil
}

// component inspects parts[index], located at absolute, without following a
// symbolic link. Every component except the last one must be a directory.
func component(absolute string, parts []string, index int) (os.FileInfo, error) {
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s", ErrSymlink, filepath.ToSlash(filepath.Join(parts[:index+1]...)))
	}
	if index < len(parts)-1 && !info.IsDir() {
		return nil, fmt.Errorf("path component is not a directory: %s", filepath.ToSlash(filepath.Join(parts[:index+1]...)))
	}
	return info, nil
}

func hasWindowsVolume(path string) bool {
	return len(path) >= 2 && path[1] == ':' && (path[0] >= 'A' && path[0] <= 'Z' || path[0] >= 'a' && path[0] <= 'z')
}
