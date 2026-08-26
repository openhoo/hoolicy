package fix

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openhoo/hoolicy/internal/safepath"
	"github.com/openhoo/hoolicy/sdk"
)

type Plan struct {
	Root  string
	Files []FilePlan
}

type FilePlan struct {
	Path string
	Mode os.FileMode
	Old  []byte
	New  []byte
}

type stagedFile struct {
	target, temp, backup string
	existed              bool
}

func Build(root string, findings []sdk.Finding, selected []string) (*Plan, error) {
	selectedRules := make(map[string]bool, len(selected))
	for _, id := range selected {
		selectedRules[id] = true
	}
	editsByPath := make(map[string][]sdk.Edit)
	for _, item := range findings {
		if item.Waived || item.Fix == nil || (len(selectedRules) > 0 && !selectedRules[item.RuleID]) {
			continue
		}
		for _, edit := range item.Fix.Edits {
			editsByPath[filepath.ToSlash(edit.Path)] = append(editsByPath[filepath.ToSlash(edit.Path)], edit)
		}
	}
	if len(editsByPath) == 0 {
		return nil, fmt.Errorf("no safe fixes available for selected findings")
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	plan := &Plan{Root: absoluteRoot}
	paths := make([]string, 0, len(editsByPath))
	for path := range editsByPath {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		clean, absolute, err := safePath(absoluteRoot, path)
		if err != nil {
			return nil, err
		}
		if dirty(absoluteRoot, clean) {
			return nil, fmt.Errorf("refusing to fix dirty target file %s", clean)
		}
		info, statErr := os.Lstat(absolute)
		var old []byte
		mode := os.FileMode(0o644)
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return nil, fmt.Errorf("refusing to fix non-regular file %s", clean)
			}
			mode = info.Mode().Perm()
			old, err = os.ReadFile(absolute)
			if err != nil {
				return nil, err
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return nil, statErr
		}
		edits := editsByPath[path]
		sort.Slice(edits, func(i, j int) bool { return edits[i].Start < edits[j].Start })
		for i, edit := range edits {
			expected := digest(old)
			if len(old) == 0 && errors.Is(statErr, os.ErrNotExist) {
				expected = "missing"
			}
			if edit.ExpectedSHA256 != expected {
				return nil, fmt.Errorf("%s changed after finding was produced", clean)
			}
			if edit.Start < 0 || edit.End < edit.Start || edit.End > len(old) {
				return nil, fmt.Errorf("%s contains out-of-range edit", clean)
			}
			if i > 0 && edits[i-1].End > edit.Start {
				return nil, fmt.Errorf("%s contains overlapping edits", clean)
			}
		}
		updated := append([]byte(nil), old...)
		for i := len(edits) - 1; i >= 0; i-- {
			edit := edits[i]
			updated = append(append(append([]byte(nil), updated[:edit.Start]...), edit.Replacement...), updated[edit.End:]...)
		}
		plan.Files = append(plan.Files, FilePlan{Path: clean, Mode: mode, Old: old, New: updated})
	}
	return plan, nil
}

func (p *Plan) Diff() string {
	var output strings.Builder
	for _, file := range p.Files {
		output.WriteString("--- a/")
		output.WriteString(file.Path)
		output.WriteByte('\n')
		output.WriteString("+++ b/")
		output.WriteString(file.Path)
		output.WriteByte('\n')
		oldLines := strings.Split(strings.TrimSuffix(string(file.Old), "\n"), "\n")
		newLines := strings.Split(strings.TrimSuffix(string(file.New), "\n"), "\n")
		if len(file.Old) == 0 {
			oldLines = nil
		}
		if len(file.New) == 0 {
			newLines = nil
		}
		prefix, suffix := sharedContext(oldLines, newLines)
		start := prefix - 2
		if start < 0 {
			start = 0
		}
		oldEnd := len(oldLines) - suffix + 2
		if oldEnd > len(oldLines) {
			oldEnd = len(oldLines)
		}
		newEnd := len(newLines) - suffix + 2
		if newEnd > len(newLines) {
			newEnd = len(newLines)
		}
		output.WriteString(fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", start+1, oldEnd-start, start+1, newEnd-start))
		for i := start; i < prefix; i++ {
			output.WriteString(" ")
			output.WriteString(oldLines[i])
			output.WriteByte('\n')
		}
		for i := prefix; i < len(oldLines)-suffix; i++ {
			output.WriteString("-")
			output.WriteString(oldLines[i])
			output.WriteByte('\n')
		}
		for i := prefix; i < len(newLines)-suffix; i++ {
			output.WriteString("+")
			output.WriteString(newLines[i])
			output.WriteByte('\n')
		}
		for i := len(oldLines) - suffix; i < oldEnd; i++ {
			if i >= 0 && i < len(oldLines) {
				output.WriteString(" ")
				output.WriteString(oldLines[i])
				output.WriteByte('\n')
			}
		}
	}
	return output.String()
}

func (p *Plan) Apply() error {
	stages := make([]stagedFile, 0, len(p.Files))
	cleanup := func() {
		for _, entry := range stages {
			os.Remove(entry.temp)
		}
	}
	defer cleanup()
	for _, file := range p.Files {
		_, target, err := safePath(p.Root, file.Path)
		if err != nil {
			return err
		}
		current, readErr := os.ReadFile(target)
		if readErr == nil {
			if !bytes.Equal(current, file.Old) {
				return fmt.Errorf("%s changed after preview", file.Path)
			}
		} else if !errors.Is(readErr, os.ErrNotExist) || len(file.Old) > 0 {
			return fmt.Errorf("%s changed after preview", file.Path)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		temporary, err := os.CreateTemp(filepath.Dir(target), ".hoolicy-fix-*")
		if err != nil {
			return err
		}
		if err := temporary.Chmod(file.Mode); err != nil {
			temporary.Close()
			return err
		}
		if _, err := temporary.Write(file.New); err != nil {
			temporary.Close()
			return err
		}
		if err := temporary.Sync(); err != nil {
			temporary.Close()
			return err
		}
		if err := temporary.Close(); err != nil {
			return err
		}
		_, statErr := os.Stat(target)
		backup, err := reserveName(filepath.Dir(target), ".hoolicy-backup-*")
		if err != nil {
			_ = os.Remove(temporary.Name())
			return err
		}
		stages = append(stages, stagedFile{target: target, temp: temporary.Name(), backup: backup, existed: statErr == nil})
	}
	for index, entry := range stages {
		if entry.existed {
			if err := os.Rename(entry.target, entry.backup); err != nil {
				return rollback(stages[:index], err)
			}
		}
		if err := os.Rename(entry.temp, entry.target); err != nil {
			if entry.existed {
				_ = os.Rename(entry.backup, entry.target)
			}
			return rollback(stages[:index], err)
		}
	}
	for _, entry := range stages {
		os.Remove(entry.backup)
	}
	return nil
}

func rollback(applied []stagedFile, cause error) error {
	for index := len(applied) - 1; index >= 0; index-- {
		entry := applied[index]
		_ = os.Remove(entry.target)
		if entry.existed {
			_ = os.Rename(entry.backup, entry.target)
		}
	}
	return cause
}

func reserveName(directory, pattern string) (string, error) {
	file, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return "", err
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	if err := os.Remove(name); err != nil {
		return "", err
	}
	return name, nil
}

func sharedContext(left, right []string) (int, int) {
	prefix := 0
	for prefix < len(left) && prefix < len(right) && left[prefix] == right[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(left)-prefix && suffix < len(right)-prefix && left[len(left)-1-suffix] == right[len(right)-1-suffix] {
		suffix++
	}
	return prefix, suffix
}
func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func dirty(root, path string) bool {
	result := exec.Command("git", "-C", root, "status", "--porcelain=v1", "--", path)
	output, err := result.Output()
	return err == nil && len(bytes.TrimSpace(output)) > 0
}
func safePath(root, path string) (string, string, error) {
	clean, absolute, err := safepath.Writable(root, path)
	if err != nil {
		return "", "", fmt.Errorf("unsafe fix path: %w", err)
	}
	return clean, absolute, nil
}
