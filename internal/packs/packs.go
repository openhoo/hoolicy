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
	"unicode"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/ocipack"
	"github.com/openhoo/hoolicy/internal/packarchive"
	"github.com/openhoo/hoolicy/internal/safepath"
	"github.com/openhoo/hoolicy/sdk"
)

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

func Resolve(project *config.Project, toolVersions ...string) ([]sdk.Rule, error) {
	toolVersion := "dev"
	if len(toolVersions) > 0 {
		toolVersion = toolVersions[0]
	}
	lockPath := filepath.Join(project.Root, config.DefaultLockfile)
	var lock *config.Lock
	remoteCount := 0
	for _, reference := range project.Packs {
		if reference.Git != "" || reference.OCI != "" {
			remoteCount++
		}
	}
	loaded, lockErr := config.LoadLock(lockPath)
	if lockErr == nil {
		lock = loaded
	} else if remoteCount > 0 {
		return nil, fmt.Errorf("remote packs require a valid %s: %w", config.DefaultLockfile, lockErr)
	} else if !errors.Is(lockErr, os.ErrNotExist) {
		return nil, fmt.Errorf("invalid %s: %w", config.DefaultLockfile, lockErr)
	}
	configuredRemote := make(map[string]bool, remoteCount)
	for _, reference := range project.Packs {
		if reference.Git != "" || reference.OCI != "" {
			configuredRemote[reference.Name] = true
		}
	}
	lockedByName := make(map[string]config.LockedPack)
	if lock != nil {
		for _, entry := range lock.Packs {
			if _, exists := lockedByName[entry.Name]; exists {
				return nil, fmt.Errorf("lock contains duplicate pack %s", entry.Name)
			}
			if !configuredRemote[entry.Name] {
				return nil, fmt.Errorf("lock contains stale pack %s not present as a remote project pack", entry.Name)
			}
			lockedByName[entry.Name] = entry
		}
	}
	var rules []sdk.Rule
	seen := make(map[string]string)
	for _, reference := range project.Packs {
		path := reference.Path
		if reference.Git != "" || reference.OCI != "" {
			locked, exists := lockedByName[reference.Name]
			if !exists {
				return nil, fmt.Errorf("pack %s is absent from lock", reference.Name)
			}
			if locked.Git != reference.Git || locked.Ref != reference.Ref || locked.Subdir != reference.Subdir || locked.OCI != reference.OCI {
				return nil, fmt.Errorf("pack %s config and lock disagree", reference.Name)
			}
			if reference.Git != "" && !commitPattern.MatchString(locked.Commit) {
				return nil, fmt.Errorf("pack %s lock has invalid commit", reference.Name)
			}
			expectedVendor := filepath.ToSlash(filepath.Join(".hoolicy", "vendor", reference.Name))
			if locked.Vendor != expectedVendor {
				return nil, fmt.Errorf("pack %s lock has unexpected vendor path %s", reference.Name, locked.Vendor)
			}
			path = locked.Vendor
			_, absolute, err := safepath.Existing(project.Root, path)
			if err != nil {
				return nil, fmt.Errorf("pack %s: %w", reference.Name, err)
			}
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
		if err := config.ValidatePackCompatibility(pack, toolVersion); err != nil {
			return nil, err
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

func Sync(project *config.Project, name string, toolVersions ...string) (config.LockedPack, error) {
	acquired, err := acquire(project, name, toolVersions...)
	if err != nil {
		return config.LockedPack{}, err
	}
	defer acquired.cleanup()
	if err := installAcquired([]*acquiredPack{acquired}, nil); err != nil {
		return config.LockedPack{}, err
	}
	return acquired.locked, nil
}

type acquiredPack struct {
	locked config.LockedPack
	staged string
	vendor string
}

func (pack *acquiredPack) cleanup() {
	_ = os.RemoveAll(pack.staged)
}

func acquire(project *config.Project, name string, toolVersions ...string) (*acquiredPack, error) {
	var reference *config.PackRef
	for index := range project.Packs {
		if project.Packs[index].Name == name {
			reference = &project.Packs[index]
			break
		}
	}
	if reference == nil {
		return nil, fmt.Errorf("unknown pack %s", name)
	}
	if reference.Git == "" && reference.OCI == "" {
		return nil, fmt.Errorf("pack %s is local and cannot be synced", name)
	}
	toolVersion := "dev"
	if len(toolVersions) > 0 {
		toolVersion = toolVersions[0]
	}
	if reference.OCI != "" {
		return acquireOCI(project, *reference, toolVersion)
	}
	return acquireGit(project, *reference, toolVersion)
}

func acquireGit(project *config.Project, reference config.PackRef, toolVersion string) (*acquiredPack, error) {
	temporary, err := os.MkdirTemp("", "hoolicy-pack-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(temporary)
	repository := filepath.Join(temporary, "repository")
	commands := [][]string{
		{"init", "--quiet", repository},
		{"-C", repository, "remote", "add", "origin", reference.Git},
		{"-C", repository, "fetch", "--quiet", "--depth", "1", "origin", "--", reference.Ref},
		{"-C", repository, "checkout", "--quiet", "--detach", "FETCH_HEAD"},
	}
	for _, args := range commands {
		command := exec.Command("git", args...)
		command.Env = os.Environ()
		output, commandErr := command.CombinedOutput()
		if commandErr != nil {
			return nil, fmt.Errorf("git %s failed: %s", args[0], sanitizeGitOutput(string(output)))
		}
	}
	commitBytes, err := exec.Command("git", "-C", repository, "rev-parse", "HEAD").Output()
	if err != nil {
		return nil, err
	}
	commit := strings.TrimSpace(string(commitBytes))
	if !commitPattern.MatchString(commit) {
		return nil, fmt.Errorf("git returned invalid commit")
	}
	source := repository
	if reference.Subdir != "" {
		_, source, err = safepath.Existing(repository, reference.Subdir)
		if err != nil {
			return nil, fmt.Errorf("pack %s subdir: %w", reference.Name, err)
		}
	}
	pack, err := config.LoadPack(source)
	if err != nil {
		return nil, err
	}
	if pack.Name != reference.Name {
		return nil, fmt.Errorf("pack name %s does not match requested %s", pack.Name, reference.Name)
	}
	if err := config.ValidatePackCompatibility(pack, toolVersion); err != nil {
		return nil, err
	}
	if _, _, err := packarchive.Build(source); err != nil {
		return nil, fmt.Errorf("pack content limits: %w", err)
	}
	vendorRelative := filepath.ToSlash(filepath.Join(".hoolicy", "vendor", reference.Name))
	_, vendor, err := safepath.Writable(project.Root, vendorRelative)
	if err != nil {
		return nil, err
	}
	vendorParent := filepath.Dir(vendor)
	if err := os.MkdirAll(vendorParent, 0o755); err != nil {
		return nil, err
	}
	staged, err := os.MkdirTemp(vendorParent, "."+reference.Name+"-stage-*")
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(staged)
		}
	}()
	if err := copyTree(source, staged); err != nil {
		return nil, err
	}
	digest, err := Digest(staged)
	if err != nil {
		return nil, err
	}
	complete = true
	return &acquiredPack{
		locked: config.LockedPack{Name: reference.Name, Git: reference.Git, Ref: reference.Ref, Subdir: reference.Subdir, Commit: commit, Digest: digest, Vendor: vendorRelative, Release: pack.Release},
		staged: staged,
		vendor: vendor,
	}, nil
}

func acquireOCI(project *config.Project, reference config.PackRef, toolVersion string) (*acquiredPack, error) {
	vendorRelative := filepath.ToSlash(filepath.Join(".hoolicy", "vendor", reference.Name))
	_, vendor, err := safepath.Writable(project.Root, vendorRelative)
	if err != nil {
		return nil, err
	}
	parent := filepath.Dir(vendor)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, err
	}
	staged, err := os.MkdirTemp(parent, "."+reference.Name+"-oci-stage-*")
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(staged)
		}
	}()
	pulled, err := ocipack.Pull(project.Root, reference.OCI, project.Trust, staged)
	if err != nil {
		return nil, err
	}
	pack, err := config.LoadPack(staged)
	if err != nil {
		return nil, err
	}
	if pack.Name != reference.Name {
		return nil, fmt.Errorf("pack name %s does not match requested %s", pack.Name, reference.Name)
	}
	if pulled.PackName != pack.Name || pulled.Release != pack.Release {
		return nil, errors.New("OCI release manifest and pack manifest disagree")
	}
	if err := config.ValidatePackCompatibility(pack, toolVersion); err != nil {
		return nil, err
	}
	treeDigest, err := Digest(staged)
	if err != nil {
		return nil, err
	}
	complete = true
	return &acquiredPack{
		locked: config.LockedPack{Name: reference.Name, OCI: reference.OCI, ManifestDigest: pulled.ManifestDigest, PackDigest: pulled.PackDigest, VerifiedBy: pulled.VerifiedBy, Digest: treeDigest, Vendor: vendorRelative, Release: pack.Release},
		staged: staged,
		vendor: vendor,
	}, nil
}

func UpdateLock(project *config.Project, names []string, toolVersions ...string) (*config.Lock, error) {
	remote := make(map[string]bool)
	for _, reference := range project.Packs {
		if reference.Git != "" || reference.OCI != "" {
			remote[reference.Name] = true
		}
	}
	selected := make(map[string]bool, len(names))
	for _, name := range names {
		if selected[name] {
			return nil, fmt.Errorf("pack %s was selected more than once", name)
		}
		selected[name] = true
		if !remote[name] {
			return nil, fmt.Errorf("pack %s is not a configured remote pack", name)
		}
	}
	lockPath := filepath.Join(project.Root, config.DefaultLockfile)
	lock := &config.Lock{Version: config.CurrentVersion}
	if existing, err := config.LoadLock(lockPath); err == nil {
		lock = existing
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	byName := make(map[string]config.LockedPack)
	for _, entry := range lock.Packs {
		if remote[entry.Name] {
			byName[entry.Name] = entry
		}
	}
	acquired := make([]*acquiredPack, 0, len(names))
	defer func() {
		for _, pack := range acquired {
			pack.cleanup()
		}
	}()
	for _, name := range names {
		pack, err := acquire(project, name, toolVersions...)
		if err != nil {
			return nil, err
		}
		acquired = append(acquired, pack)
		entry := pack.locked
		if previous, exists := byName[name]; exists && releaseLess(entry.Release, previous.Release) {
			return nil, fmt.Errorf("pack %s downgrade from %s to %s is forbidden", name, previous.Release, entry.Release)
		}
		byName[name] = entry
	}
	lock.Packs = lock.Packs[:0]
	for _, entry := range byName {
		lock.Packs = append(lock.Packs, entry)
	}
	if err := installAcquired(acquired, func() error { return config.SaveLock(lockPath, *lock) }); err != nil {
		return nil, err
	}
	return lock, nil
}

type installedPack struct {
	pack      *acquiredPack
	backup    string
	installed bool
}

func installAcquired(packs []*acquiredPack, commit func() error) error {
	states := make([]installedPack, 0, len(packs))
	rollback := func(cause error) error {
		var failures []string
		for index := len(states) - 1; index >= 0; index-- {
			state := states[index]
			if state.installed {
				if err := os.RemoveAll(state.pack.vendor); err != nil {
					failures = append(failures, fmt.Sprintf("remove %s: %v", state.pack.vendor, err))
					continue
				}
			}
			if state.backup != "" {
				if err := os.Rename(state.backup, state.pack.vendor); err != nil {
					failures = append(failures, fmt.Sprintf("restore %s from %s: %v", state.pack.vendor, state.backup, err))
				}
			}
		}
		if len(failures) > 0 {
			return fmt.Errorf("%w; rollback failed: %s", cause, strings.Join(failures, "; "))
		}
		return cause
	}
	for _, pack := range packs {
		state := installedPack{pack: pack}
		if _, err := os.Lstat(pack.vendor); err == nil {
			reserved, reserveErr := os.MkdirTemp(filepath.Dir(pack.vendor), "."+filepath.Base(pack.vendor)+"-backup-*")
			if reserveErr != nil {
				return rollback(reserveErr)
			}
			if removeErr := os.Remove(reserved); removeErr != nil {
				return rollback(removeErr)
			}
			state.backup = reserved
			if err := os.Rename(pack.vendor, state.backup); err != nil {
				return rollback(err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return rollback(err)
		}
		states = append(states, state)
		if err := os.Rename(pack.staged, pack.vendor); err != nil {
			return rollback(err)
		}
		states[len(states)-1].installed = true
	}
	if commit != nil {
		if err := commit(); err != nil {
			return rollback(err)
		}
	}
	for _, state := range states {
		if state.backup != "" {
			if err := os.RemoveAll(state.backup); err != nil {
				return fmt.Errorf("installed packs but could not remove recovery backup %s: %w", state.backup, err)
			}
		}
	}
	return nil
}

func releaseLess(left, right string) bool {
	comparison, err := config.CompareSemanticVersions(left, right)
	return err == nil && comparison < 0
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
		return copyFile(path, destination)
	})
}

func copyFile(source, target string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		_ = input.Close()
		return err
	}
	_, copyErr := io.Copy(output, input)
	inputCloseErr := input.Close()
	outputCloseErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	if inputCloseErr != nil {
		return inputCloseErr
	}
	return outputCloseErr
}

func replaceDirectory(source, target string) error {
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	backup := ""
	if _, err := os.Lstat(target); err == nil {
		reserved, reserveErr := os.MkdirTemp(parent, "."+filepath.Base(target)+"-backup-*")
		if reserveErr != nil {
			return reserveErr
		}
		if removeErr := os.Remove(reserved); removeErr != nil {
			return removeErr
		}
		backup = reserved
		if err := os.Rename(target, backup); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(source, target); err != nil {
		if backup != "" {
			if restoreErr := os.Rename(backup, target); restoreErr != nil {
				return fmt.Errorf("install pack: %w; restore previous vendor from %s: %v", err, backup, restoreErr)
			}
		}
		return err
	}
	if backup != "" {
		return os.RemoveAll(backup)
	}
	return nil
}

func sanitizeGitOutput(value string) string {
	value = strings.TrimSpace(strings.Map(func(character rune) rune {
		if character == '\n' {
			return character
		}
		if unicode.IsControl(character) {
			return ' '
		}
		return character
	}, value))
	if value == "" {
		return "command failed"
	}
	lines := strings.Split(value, "\n")
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
	value = strings.Join(lines, " ")
	runes := []rune(value)
	if len(runes) > 1024 {
		value = string(runes[:1024]) + "..."
	}
	return value
}
