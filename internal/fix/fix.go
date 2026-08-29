package fix

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openhoo/hoolicy/internal/repository"
	"github.com/openhoo/hoolicy/internal/safepath"
	"github.com/openhoo/hoolicy/sdk"
)

type Plan struct {
	Root  string
	Files []FilePlan
}

type FilePlan struct {
	Path   string
	Mode   os.FileMode
	Exists bool
	Old    []byte
	New    []byte
}

type stagedFile struct {
	path, target, temp, backup string
	existed                    bool
	old                        []byte
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
		isDirty, statusErr := dirty(absoluteRoot, clean)
		if statusErr != nil {
			return nil, statusErr
		}
		if isDirty {
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
		plan.Files = append(plan.Files, FilePlan{Path: clean, Mode: mode, Exists: statErr == nil, Old: old, New: updated})
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

func (p *Plan) Apply() (resultErr error) {
	stages := make([]stagedFile, 0, len(p.Files))
	defer func() {
		if err := cleanupStagedTemps(stages); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	for _, file := range p.Files {
		stage, err := p.stageFile(file)
		if err != nil {
			return err
		}
		stages = append(stages, stage)
	}
	if err := p.installStages(stages); err != nil {
		return err
	}
	if err := removeBackups(stages); err != nil {
		return fmt.Errorf("fixes applied but backup cleanup failed: %w", err)
	}
	return nil
}

func (p *Plan) stageFile(file FilePlan) (stage stagedFile, resultErr error) {
	_, target, err := safePath(p.Root, file.Path)
	if err != nil {
		return stage, err
	}
	current, readErr := os.ReadFile(target)
	if file.Exists && (readErr != nil || !bytes.Equal(current, file.Old)) || !file.Exists && !errors.Is(readErr, os.ErrNotExist) {
		return stage, fmt.Errorf("%s changed after preview", file.Path)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return stage, err
	}
	_, verifiedTarget, err := safePath(p.Root, file.Path)
	if err != nil || verifiedTarget != target {
		if err == nil {
			err = fmt.Errorf("fix target changed after directory creation: %s", file.Path)
		}
		return stage, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".hoolicy-fix-*")
	if err != nil {
		return stage, err
	}
	stage = stagedFile{path: file.Path, target: target, temp: temporary.Name(), existed: file.Exists, old: append([]byte(nil), file.Old...)}
	defer func() {
		if resultErr != nil {
			if err := os.Remove(stage.temp); err != nil && !errors.Is(err, os.ErrNotExist) {
				resultErr = errors.Join(resultErr, fmt.Errorf("remove staged fix %s: %w", stage.temp, err))
			}
		}
	}()
	if err := temporary.Chmod(file.Mode); err != nil {
		return stage, errors.Join(err, temporary.Close())
	}
	if _, err := temporary.Write(file.New); err != nil {
		return stage, errors.Join(err, temporary.Close())
	}
	if err := temporary.Sync(); err != nil {
		return stage, errors.Join(err, temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return stage, err
	}
	stage.backup, err = reserveName(filepath.Dir(target), ".hoolicy-backup-*")
	if err != nil {
		return stage, err
	}
	return stage, nil
}

func (p *Plan) installStages(stages []stagedFile) error {
	for index, entry := range stages {
		_, verifiedTarget, err := safePath(p.Root, entry.path)
		if err != nil || verifiedTarget != entry.target {
			if err == nil {
				err = fmt.Errorf("fix target changed before apply: %s", entry.path)
			}
			return rollback(stages[:index], err)
		}
		current, readErr := os.ReadFile(entry.target)
		if entry.existed && (readErr != nil || !bytes.Equal(current, entry.old)) || !entry.existed && !errors.Is(readErr, os.ErrNotExist) {
			return rollback(stages[:index], fmt.Errorf("%s changed after staging", entry.path))
		}
		if entry.existed {
			if err := os.Rename(entry.target, entry.backup); err != nil {
				return rollback(stages[:index], err)
			}
		}
		if err := os.Rename(entry.temp, entry.target); err != nil {
			return rollback(stages[:index+1], err)
		}
	}
	return nil
}

func removeBackups(stages []stagedFile) error {
	var cleanupErrors []error
	for _, entry := range stages {
		if err := os.Remove(entry.backup); err != nil && !errors.Is(err, os.ErrNotExist) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove recovery backup %s: %w", entry.backup, err))
		}
	}
	if len(cleanupErrors) > 0 {
		return errors.Join(cleanupErrors...)
	}
	return nil
}

func rollback(applied []stagedFile, cause error) error {
	var failures []error
	for index := len(applied) - 1; index >= 0; index-- {
		entry := applied[index]
		if err := os.Remove(entry.target); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, fmt.Errorf("remove partially applied %s: %w", entry.path, err))
			continue
		}
		if entry.existed {
			if err := os.Rename(entry.backup, entry.target); err != nil {
				failures = append(failures, fmt.Errorf("restore %s from %s: %w", entry.path, entry.backup, err))
			}
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%w; rollback failed: %v", cause, errors.Join(failures...))
	}
	return cause
}

func cleanupStagedTemps(stages []stagedFile) error {
	var failures []error
	for _, entry := range stages {
		if err := os.Remove(entry.temp); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, fmt.Errorf("remove staged fix %s: %w", entry.temp, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("fix staging cleanup failed: %w", errors.Join(failures...))
	}
	return nil
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
func dirty(root, path string) (bool, error) {
	dirty, err := repository.GitPathDirty(root, path)
	if err != nil {
		return false, fmt.Errorf("cannot verify Git status for %s: %w", path, err)
	}
	return dirty, nil
}
func safePath(root, path string) (string, string, error) {
	clean, absolute, err := safepath.Writable(root, path)
	if err != nil {
		return "", "", fmt.Errorf("unsafe fix path: %w", err)
	}
	return clean, absolute, nil
}
