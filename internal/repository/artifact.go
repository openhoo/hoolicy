package repository

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"github.com/openhoo/hoolicy/internal/safepath"
	"golang.org/x/text/unicode/norm"
)

// ArtifactOutputPath resolves an output without creating its parents and
// requires it to stay outside evaluated source, or be untracked and ignored by
// Git. Repository metadata is never an artifact destination.
func ArtifactOutputPath(root, output string) (string, error) {
	absolute, err := CanonicalOutputPath(output)
	if err != nil {
		return "", err
	}
	if err := protectGitMetadata(root, output, absolute); err != nil {
		return "", err
	}
	boundary, found := findGitRoot(root)
	if !found {
		boundary = root
	}
	boundary, err = filepath.EvalSymlinks(boundary)
	if err != nil {
		return "", err
	}
	boundary, err = filepath.Abs(boundary)
	if err != nil {
		return "", err
	}
	inside, err := PathWithin(boundary, absolute)
	if err != nil {
		return "", err
	}
	if !inside {
		return absolute, nil
	}
	relative, err := filepath.Rel(boundary, absolute)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("artifact output %s is inside evaluated source; choose an output outside %s", output, boundary)
	}
	command := exec.Command("git", "-C", boundary, "check-ignore", "--quiet", "--", filepath.ToSlash(relative))
	if err := command.Run(); err == nil {
		return absolute, nil
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
		return "", fmt.Errorf("cannot verify Git ignore status for artifact output %s; choose an output outside %s: %w", output, boundary, err)
	}
	return "", fmt.Errorf("artifact output %s would change repository inputs or dirty state; choose an untracked Git-ignored output or an output outside %s", output, boundary)
}

// ReportOutputPath allows reports inside source while protecting Git metadata.
// Atomic report replacement may replace a final symlink without following it.
func ReportOutputPath(root, output string) (string, error) {
	absolute, err := canonicalOutputPath(output, true)
	if err != nil {
		return "", err
	}
	if err := protectGitMetadata(root, output, absolute); err != nil {
		return "", err
	}
	return absolute, nil
}

func protectGitMetadata(root, output, absolute string) error {
	if safepath.GitMetadataPath(filepath.ToSlash(absolute)) || safepath.GitMetadataPath(filepath.ToSlash(output)) {
		return fmt.Errorf("artifact output %s targets Git metadata", output)
	}
	boundary, found := findGitRoot(root)
	if !found {
		return nil
	}
	metadata, err := gitMetadataDirectories(boundary)
	if err != nil {
		return err
	}
	for _, directory := range metadata {
		inside, err := PathWithin(directory, absolute)
		if err != nil {
			return err
		}
		if inside {
			return fmt.Errorf("artifact output %s targets Git metadata", output)
		}
	}
	return nil
}

// PathWithin compares physical artifact and policy locations portably. A
// different Windows volume is outside; case aliases are treated conservatively
// on platforms where the default filesystem is case insensitive.
func PathWithin(directory, path string) (bool, error) {
	if !strings.EqualFold(filepath.VolumeName(directory), filepath.VolumeName(path)) {
		return false, nil
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		directory, path = insensitivePath(directory), insensitivePath(path)
	}
	relative, err := filepath.Rel(directory, path)
	if err != nil {
		return false, err
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)), nil
}

func insensitivePath(value string) string {
	return strings.Map(func(character rune) rune {
		minimum := character
		for folded := unicode.SimpleFold(character); folded != character; folded = unicode.SimpleFold(folded) {
			minimum = min(minimum, folded)
		}
		return minimum
	}, norm.NFC.String(value))
}

func gitMetadataDirectories(root string) ([]string, error) {
	metadata := filepath.Join(root, ".git")
	info, err := os.Stat(metadata)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		data, err := os.ReadFile(metadata)
		if err != nil {
			return nil, err
		}
		line := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
		if !strings.HasPrefix(line, "gitdir: ") {
			return nil, fmt.Errorf("invalid Git metadata indirection: %s", metadata)
		}
		metadata = strings.TrimSpace(strings.TrimPrefix(line, "gitdir: "))
		if metadata == "" {
			return nil, fmt.Errorf("empty Git metadata indirection")
		}
		if !filepath.IsAbs(metadata) {
			metadata = filepath.Join(root, metadata)
		}
	}
	metadata, err = filepath.EvalSymlinks(metadata)
	if err != nil {
		return nil, err
	}
	directories := []string{metadata}
	data, err := os.ReadFile(filepath.Join(metadata, "commondir"))
	if errors.Is(err, os.ErrNotExist) {
		return directories, nil
	}
	if err != nil {
		return nil, err
	}
	common := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
	if common == "" {
		return nil, fmt.Errorf("empty Git common directory")
	}
	if !filepath.IsAbs(common) {
		common = filepath.Join(metadata, common)
	}
	common, err = filepath.EvalSymlinks(common)
	if err != nil {
		return nil, err
	}
	return append(directories, common), nil
}

// CanonicalOutputPath resolves existing parent aliases while leaving a missing
// output and missing parent directories untouched. An existing final symlink
// is rejected so an artifact path cannot refer to two different files.
func CanonicalOutputPath(output string) (string, error) {
	return canonicalOutputPath(output, false)
}

func canonicalOutputPath(output string, allowFinalSymlink bool) (string, error) {
	absolute, err := filepath.Abs(output)
	if err != nil {
		return "", err
	}
	if info, err := os.Lstat(absolute); err == nil {
		if !info.Mode().IsRegular() && !(allowFinalSymlink && info.Mode()&os.ModeSymlink != 0) {
			return "", fmt.Errorf("artifact output is not a regular file: %s", output)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	directory := filepath.Dir(absolute)
	tail := []string{filepath.Base(absolute)}
	for {
		resolved, err := filepath.EvalSymlinks(directory)
		if err == nil {
			info, err := os.Stat(resolved)
			if err != nil {
				return "", err
			}
			if !info.IsDir() {
				return "", fmt.Errorf("artifact output parent is not a directory: %s", directory)
			}
			for index := len(tail) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, tail[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		// An existing dangling symlink is not a missing directory. Leaving
		// that alias unresolved could hide overlap with another output.
		if info, inspectErr := os.Lstat(directory); inspectErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("artifact output parent symbolic link cannot be resolved: %s", directory)
			}
		} else if !errors.Is(inspectErr, os.ErrNotExist) {
			return "", inspectErr
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", err
		}
		tail = append(tail, filepath.Base(directory))
		directory = parent
	}
}
