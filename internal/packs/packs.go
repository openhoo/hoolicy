package packs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/safepath"
	"github.com/openhoo/hoolicy/sdk"
)

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

func Resolve(project *config.Project) ([]sdk.Rule, error) {
	lockPath := filepath.Join(project.Root, config.DefaultLockfile)
	var lock *config.Lock
	remoteCount := 0
	for _, reference := range project.Packs {
		if reference.Git != "" {
			remoteCount++
		}
	}
	if remoteCount > 0 {
		loaded, err := config.LoadLock(lockPath)
		if err != nil {
			return nil, fmt.Errorf("remote packs require a valid %s: %w", config.DefaultLockfile, err)
		}
		lock = loaded
	}
	lockedByName := make(map[string]config.LockedPack)
	if lock != nil {
		for _, entry := range lock.Packs {
			if _, exists := lockedByName[entry.Name]; exists {
				return nil, fmt.Errorf("lock contains duplicate pack %s", entry.Name)
			}
			lockedByName[entry.Name] = entry
		}
	}
	var rules []sdk.Rule
	seen := make(map[string]string)
	for _, reference := range project.Packs {
		path := reference.Path
		if reference.Git != "" {
			locked, exists := lockedByName[reference.Name]
			if !exists {
				return nil, fmt.Errorf("pack %s is absent from lock", reference.Name)
			}
			if locked.Git != reference.Git || locked.Ref != reference.Ref || locked.Subdir != reference.Subdir {
				return nil, fmt.Errorf("pack %s config and lock disagree", reference.Name)
			}
			if !commitPattern.MatchString(locked.Commit) {
				return nil, fmt.Errorf("pack %s lock has invalid commit", reference.Name)
			}
			path = locked.Vendor
			if path == "" {
				path = filepath.ToSlash(filepath.Join(".hoolicy", "vendor", reference.Name))
			}
			absolute := filepath.Join(project.Root, filepath.FromSlash(path))
			digest, err := Digest(absolute)
			if err != nil {
				return nil, fmt.Errorf("pack %s: %w", reference.Name, err)
			}
			if digest != locked.Digest {
				return nil, fmt.Errorf("pack %s digest mismatch: lock %s, vendor %s", reference.Name, locked.Digest, digest)
			}
		}
		_, absolute, err := safepath.Existing(project.Root, path)
		if err != nil {
			return nil, fmt.Errorf("pack %s: %w", reference.Name, err)
		}
		pack, err := config.LoadPack(absolute)
		if err != nil {
			return nil, err
		}
		if pack.Name != reference.Name {
			return nil, fmt.Errorf("pack reference %s loaded manifest %s", reference.Name, pack.Name)
		}
		instantiated, err := pack.Instantiate(reference.With)
		if err != nil {
			return nil, err
		}
		for _, rule := range instantiated {
			if owner, exists := seen[rule.ID]; exists {
				return nil, fmt.Errorf("duplicate rule %s from %s and %s", rule.ID, owner, reference.Name)
			}
			seen[rule.ID] = reference.Name
			rules = append(rules, rule)
		}
	}
	for _, rule := range project.Rules {
		if owner, exists := seen[rule.ID]; exists {
			return nil, fmt.Errorf("duplicate rule %s from %s and project", rule.ID, owner)
		}
		seen[rule.ID] = "project"
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules, nil
}

func Digest(root string) (string, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("pack root must be a real directory")
	}
	var paths []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if relative == ".git" && entry.IsDir() {
			return filepath.SkipDir
		}
		if relative == "." || entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic link is forbidden in pack: %s", relative)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("non-regular file is forbidden in pack: %s", relative)
		}
		paths = append(paths, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(paths)
	hash := sha256.New()
	for _, path := range paths {
		data, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if readErr != nil {
			return "", readErr
		}
		hash.Write([]byte(path))
		hash.Write([]byte{0})
		hash.Write(data)
		hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func Sync(project *config.Project, name string) (config.LockedPack, error) {
	var reference *config.PackRef
	for index := range project.Packs {
		if project.Packs[index].Name == name {
			reference = &project.Packs[index]
			break
		}
	}
	if reference == nil {
		return config.LockedPack{}, fmt.Errorf("unknown pack %s", name)
	}
	if reference.Git == "" {
		return config.LockedPack{}, fmt.Errorf("pack %s is local and cannot be synced", name)
	}
	temporary, err := os.MkdirTemp("", "hoolicy-pack-*")
	if err != nil {
		return config.LockedPack{}, err
	}
	defer os.RemoveAll(temporary)
	repository := filepath.Join(temporary, "repository")
	commands := [][]string{
		{"init", "--quiet", repository},
		{"-C", repository, "remote", "add", "origin", reference.Git},
		{"-C", repository, "fetch", "--quiet", "--depth", "1", "origin", reference.Ref},
		{"-C", repository, "checkout", "--quiet", "--detach", "FETCH_HEAD"},
	}
	for _, args := range commands {
		command := exec.Command("git", args...)
		command.Env = os.Environ()
		output, commandErr := command.CombinedOutput()
		if commandErr != nil {
			return config.LockedPack{}, fmt.Errorf("git %s failed: %s", args[0], sanitizeGitOutput(string(output)))
		}
	}
	commitBytes, err := exec.Command("git", "-C", repository, "rev-parse", "HEAD").Output()
	if err != nil {
		return config.LockedPack{}, err
	}
	commit := strings.TrimSpace(string(commitBytes))
	if !commitPattern.MatchString(commit) {
		return config.LockedPack{}, fmt.Errorf("git returned invalid commit")
	}
	source := repository
	if reference.Subdir != "" {
		source = filepath.Join(repository, filepath.FromSlash(reference.Subdir))
	}
	pack, err := config.LoadPack(source)
	if err != nil {
		return config.LockedPack{}, err
	}
	if pack.Name != reference.Name {
		return config.LockedPack{}, fmt.Errorf("pack name %s does not match requested %s", pack.Name, reference.Name)
	}
	staged := filepath.Join(temporary, "vendor")
	if err := copyTree(source, staged); err != nil {
		return config.LockedPack{}, err
	}
	digest, err := Digest(staged)
	if err != nil {
		return config.LockedPack{}, err
	}
	vendorRelative := filepath.ToSlash(filepath.Join(".hoolicy", "vendor", reference.Name))
	_, vendor, err := safepath.Writable(project.Root, vendorRelative)
	if err != nil {
		return config.LockedPack{}, err
	}
	if err := replaceDirectory(staged, vendor); err != nil {
		return config.LockedPack{}, err
	}
	return config.LockedPack{Name: reference.Name, Git: reference.Git, Ref: reference.Ref, Subdir: reference.Subdir, Commit: commit, Digest: digest, Vendor: vendorRelative, Release: pack.Release}, nil
}

func UpdateLock(project *config.Project, names []string) (*config.Lock, error) {
	lockPath := filepath.Join(project.Root, config.DefaultLockfile)
	lock := &config.Lock{Version: config.CurrentVersion}
	if existing, err := config.LoadLock(lockPath); err == nil {
		lock = existing
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	byName := make(map[string]config.LockedPack)
	for _, entry := range lock.Packs {
		byName[entry.Name] = entry
	}
	for _, name := range names {
		entry, err := Sync(project, name)
		if err != nil {
			return nil, err
		}
		byName[name] = entry
	}
	lock.Packs = lock.Packs[:0]
	for _, entry := range byName {
		lock.Packs = append(lock.Packs, entry)
	}
	if err := config.SaveLock(lockPath, *lock); err != nil {
		return nil, err
	}
	return lock, nil
}

func copyTree(source, target string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if relative == ".git" && entry.IsDir() {
			return filepath.SkipDir
		}
		destination := filepath.Join(target, relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic link is forbidden in pack: %s", relative)
		}
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o755)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("non-regular file is forbidden in pack: %s", relative)
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, input)
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}

func replaceDirectory(source, target string) error {
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	backup := target + ".hoolicy-backup"
	os.RemoveAll(backup)
	if _, err := os.Stat(target); err == nil {
		if err := os.Rename(target, backup); err != nil {
			return err
		}
	}
	if err := os.Rename(source, target); err != nil {
		if _, backupErr := os.Stat(backup); backupErr == nil {
			_ = os.Rename(backup, target)
		}
		return err
	}
	return os.RemoveAll(backup)
}

func sanitizeGitOutput(value string) string {
	lines := strings.Split(strings.TrimSpace(value), "\n")
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	for i, line := range lines {
		if at := strings.Index(line, "@"); at >= 0 {
			if scheme := strings.LastIndex(line[:at], "://"); scheme >= 0 {
				line = line[:scheme+3] + "<redacted>@" + line[at+1:]
			}
		}
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}
