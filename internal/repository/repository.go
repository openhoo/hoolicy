package repository

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/openhoo/hoolicy/internal/safepath"
	"github.com/openhoo/hoolicy/sdk"
)

type Options struct {
	BaseSHA           string
	MergeRequestTitle string
	GitContext        *sdk.GitContext
}

type Repository struct {
	root   string
	files  []sdk.File
	byPath map[string]sdk.File
	git    sdk.GitContext
}

func Open(root string, options Options) (*Repository, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	files, err := discoverFiles(absolute)
	if err != nil {
		return nil, err
	}
	byPath := make(map[string]sdk.File, len(files))
	for _, file := range files {
		byPath[file.Path] = file
	}
	repository := &Repository{root: absolute, files: files, byPath: byPath}
	if options.GitContext != nil {
		repository.git = *options.GitContext
	} else {
		gitContext, gitErr := inspectGit(absolute, options)
		if gitErr != nil {
			return nil, gitErr
		}
		repository.git = gitContext
	}
	return repository, nil
}

func (r *Repository) Root() string { return r.root }

func (r *Repository) AllFiles() []sdk.File {
	return append([]sdk.File(nil), r.files...)
}

func (r *Repository) Git() sdk.GitContext { return r.git }

func (r *Repository) Match(include, exclude []string) ([]sdk.File, error) {
	if len(include) == 0 {
		include = []string{"**/*"}
	}
	includedPatterns, err := compileGlobs(include)
	if err != nil {
		return nil, err
	}
	excludedPatterns, err := compileGlobs(exclude)
	if err != nil {
		return nil, err
	}
	matches := make([]sdk.File, 0, len(r.files))
	for _, file := range r.files {
		if !matchesCompiled(file.Path, includedPatterns) {
			continue
		}
		if !matchesCompiled(file.Path, excludedPatterns) {
			matches = append(matches, file)
		}
	}
	return matches, nil
}

func (r *Repository) Read(path string) (sdk.File, error) {
	clean, _, err := safePath(r.root, path)
	if err != nil {
		return sdk.File{}, err
	}
	file, ok := r.byPath[clean]
	if !ok {
		return sdk.File{}, fmt.Errorf("%s: file is not part of the repository snapshot", clean)
	}
	return file, nil
}

func discoverFiles(root string) ([]sdk.File, error) {
	paths, gitErr := gitFileList(root)
	if gitErr != nil {
		paths, gitErr = goGitFileList(root)
	}
	if gitErr != nil {
		if _, found := findGitRoot(root); found {
			return nil, fmt.Errorf("enumerate Git repository files: %w", gitErr)
		}
		paths = nil
		walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			relative, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			relative = filepath.ToSlash(relative)
			if entry.IsDir() && (relative == ".git" || relative == ".hoolicy/vendor" || relative == ".hoolicy-cache" || relative == "dist" || relative == "bin") {
				return filepath.SkipDir
			}
			if relative == "." || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
			paths = append(paths, relative)
			return nil
		})
		if walkErr != nil {
			return nil, walkErr
		}
	}
	sort.Strings(paths)
	files := make([]sdk.File, 0, len(paths))
	for _, path := range paths {
		if path == ".git" || strings.HasPrefix(path, ".git/") || strings.HasPrefix(path, ".hoolicy/vendor/") {
			continue
		}
		_, absolute, err := safePath(root, path)
		if errors.Is(err, safepath.ErrSymlink) || errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		info, err := os.Lstat(absolute)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		data, err := os.ReadFile(absolute)
		if err != nil {
			return nil, err
		}
		files = append(files, sdk.File{Path: filepath.ToSlash(path), Mode: info.Mode(), Data: data})
	}
	return files, nil
}

func gitFileList(root string) ([]string, error) {
	command := exec.Command("git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	output, err := command.Output()
	if err != nil {
		return nil, err
	}
	entries := bytes.Split(output, []byte{0})
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if len(entry) > 0 {
			paths = append(paths, filepath.ToSlash(string(entry)))
		}
	}
	return paths, nil
}

func goGitFileList(root string) ([]string, error) {
	gitRoot, found := findGitRoot(root)
	if !found {
		return nil, git.ErrRepositoryNotExists
	}
	repository, err := openGoGit(gitRoot)
	if err != nil {
		return nil, err
	}
	worktree, err := repository.Worktree()
	if err != nil {
		return nil, err
	}
	status, err := worktree.StatusWithOptions(git.StatusOptions{Strategy: git.Preload})
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return goGitFileListWithoutIndex(repository, worktree, gitRoot, root)
		}
		return nil, err
	}
	scope, err := filepath.Rel(gitRoot, root)
	if err != nil {
		return nil, err
	}
	scope = filepath.ToSlash(scope)
	paths := make([]string, 0, len(status))
	for path := range status {
		path = filepath.ToSlash(path)
		if scope != "." {
			prefix := strings.TrimSuffix(scope, "/") + "/"
			if !strings.HasPrefix(path, prefix) {
				continue
			}
			path = strings.TrimPrefix(path, prefix)
		}
		if path != "" {
			paths = append(paths, path)
		}
	}
	return paths, nil
}

func goGitFileListWithoutIndex(repository *git.Repository, worktree *git.Worktree, gitRoot, root string) ([]string, error) {
	tracked := make(map[string]bool)
	head, err := repository.Head()
	if err == nil {
		commit, commitErr := repository.CommitObject(head.Hash())
		if commitErr != nil {
			return nil, commitErr
		}
		tree, treeErr := commit.Tree()
		if treeErr != nil {
			return nil, treeErr
		}
		iterator := tree.Files()
		defer iterator.Close()
		if err := iterator.ForEach(func(file *object.File) error {
			tracked[filepath.ToSlash(file.Name)] = true
			return nil
		}); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, plumbing.ErrReferenceNotFound) {
		return nil, err
	}
	patterns, err := gitignore.ReadPatterns(worktree.Filesystem, nil)
	if err != nil {
		return nil, err
	}
	matcher := gitignore.NewMatcher(patterns)
	trackedDirectories := make(map[string]bool)
	for path := range tracked {
		for directory := filepath.ToSlash(filepath.Dir(path)); directory != "."; directory = filepath.ToSlash(filepath.Dir(directory)) {
			trackedDirectories[directory] = true
		}
	}
	if err := verifyReadableRepositoryExclude(gitRoot); err != nil {
		return nil, err
	}
	paths := make(map[string]bool, len(tracked))
	scope, err := filepath.Rel(gitRoot, root)
	if err != nil {
		return nil, err
	}
	scope = filepath.ToSlash(scope)
	for path := range tracked {
		if relative, included := scopedGitPath(path, scope); included {
			paths[relative] = true
		}
	}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relativeRoot, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relativeRoot = filepath.ToSlash(relativeRoot)
		relativeGit, err := filepath.Rel(gitRoot, path)
		if err != nil {
			return err
		}
		relativeGit = filepath.ToSlash(relativeGit)
		if entry.IsDir() && (relativeGit == ".git" || strings.HasPrefix(relativeGit, ".git/") || relativeGit == ".hoolicy/vendor") {
			return filepath.SkipDir
		}
		if relativeRoot == "." {
			return nil
		}
		parts := strings.Split(relativeGit, "/")
		ignored := matcher.Match(parts, entry.IsDir())
		if entry.IsDir() {
			if ignored && !trackedDirectories[relativeGit] {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() == ".gitignore" {
			if err := verifyReadableIgnoreFile(path); err != nil {
				return err
			}
		}
		if tracked[relativeGit] || !ignored {
			paths[relativeRoot] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(paths))
	for path := range paths {
		result = append(result, path)
	}
	return result, nil
}

func scopedGitPath(path, scope string) (string, bool) {
	if scope == "." {
		return path, true
	}
	prefix := strings.TrimSuffix(scope, "/") + "/"
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	return strings.TrimPrefix(path, prefix), true
}

func verifyReadableIgnoreFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("ignore file is not regular: %s", path)
	}
	_, err = os.ReadFile(path)
	return err
}

func verifyReadableRepositoryExclude(gitRoot string) error {
	metadata := filepath.Join(gitRoot, ".git")
	info, err := os.Lstat(metadata)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return nil
	}
	return verifyReadableIgnoreFile(filepath.Join(metadata, "info", "exclude"))
}

func inspectGit(root string, options Options) (sdk.GitContext, error) {
	if options.BaseSHA != "" && (strings.TrimSpace(options.BaseSHA) != options.BaseSHA || strings.HasPrefix(options.BaseSHA, "-") || strings.ContainsAny(options.BaseSHA, "\x00\r\n")) {
		return sdk.GitContext{}, fmt.Errorf("inspect Git repository: unsafe base revision %q", options.BaseSHA)
	}
	context, err := inspectGitCLI(root, options)
	if err == nil {
		return context, nil
	}
	context, fallbackErr := inspectGitGo(root, options)
	if fallbackErr == nil {
		return context, nil
	}
	if _, found := findGitRoot(root); found || options.BaseSHA != "" {
		return sdk.GitContext{}, fmt.Errorf("inspect Git repository: command: %v; fallback: %w", err, fallbackErr)
	}
	return sdk.GitContext{MergeRequestTitle: options.MergeRequestTitle, Properties: make(map[string]any)}, nil
}

func inspectGitCLI(root string, options Options) (sdk.GitContext, error) {
	context := sdk.GitContext{MergeRequestTitle: options.MergeRequestTitle, Properties: make(map[string]any)}
	status, err := gitOutput(root, "status", "--porcelain=v2", "--branch", "--untracked-files=normal")
	if err != nil {
		return sdk.GitContext{}, err
	}
	for _, line := range strings.Split(status, "\n") {
		switch {
		case strings.HasPrefix(line, "# branch.oid "):
			value := strings.TrimSpace(strings.TrimPrefix(line, "# branch.oid "))
			if value != "(initial)" {
				context.Commit = value
			}
		case strings.HasPrefix(line, "# branch.head "):
			value := strings.TrimSpace(strings.TrimPrefix(line, "# branch.head "))
			if value != "(detached)" {
				context.Branch = value
			}
		case line != "" && !strings.HasPrefix(line, "# "):
			context.Dirty = true
		}
	}
	if options.BaseSHA != "" && context.Commit != "" {
		output, err := gitOutput(root, "log", "--format=%H%x00%s", "-z", options.BaseSHA+".."+context.Commit)
		if err != nil {
			return sdk.GitContext{}, fmt.Errorf("read commit range %s..%s: %w", options.BaseSHA, context.Commit, err)
		}
		context.CommitSubjects = parseGitLog(output)
	} else if context.Commit != "" {
		output, err := gitOutput(root, "log", "-1", "--format=%H%x00%s", "-z", "HEAD")
		if err != nil {
			return sdk.GitContext{}, fmt.Errorf("read HEAD subject: %w", err)
		}
		context.CommitSubjects = parseGitLog(output)
	}
	return context, nil
}

func inspectGitGo(root string, options Options) (sdk.GitContext, error) {
	context := sdk.GitContext{MergeRequestTitle: options.MergeRequestTitle, Properties: make(map[string]any)}
	gitRoot, found := findGitRoot(root)
	if !found {
		return sdk.GitContext{}, git.ErrRepositoryNotExists
	}
	repository, err := openGoGit(gitRoot)
	if err != nil {
		return sdk.GitContext{}, err
	}
	worktree, err := repository.Worktree()
	if err != nil {
		return sdk.GitContext{}, err
	}
	status, err := worktree.Status()
	if errors.Is(err, fs.ErrPermission) {
		context.Dirty = true
		context.Properties["gitIndexReadable"] = false
	} else if err != nil {
		return sdk.GitContext{}, err
	} else {
		context.Dirty = !status.IsClean()
	}
	symbolicHead, err := repository.Reference(plumbing.HEAD, false)
	if err == nil && symbolicHead.Type() == plumbing.SymbolicReference && symbolicHead.Target().IsBranch() {
		context.Branch = symbolicHead.Target().Short()
	}
	head, err := repository.Head()
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return context, nil
	}
	if err != nil {
		return sdk.GitContext{}, err
	}
	context.Commit = head.Hash().String()
	if options.BaseSHA == "" {
		commit, err := repository.CommitObject(head.Hash())
		if err != nil {
			return sdk.GitContext{}, err
		}
		context.CommitSubjects = []sdk.Commit{{SHA: commit.Hash.String(), Subject: commitSubject(commit.Message)}}
		return context, nil
	}
	baseHash, err := repository.ResolveRevision(plumbing.Revision(options.BaseSHA))
	if err != nil {
		return sdk.GitContext{}, fmt.Errorf("resolve base revision %s: %w", options.BaseSHA, err)
	}
	excluded, err := commitSet(repository, *baseHash)
	if err != nil {
		return sdk.GitContext{}, fmt.Errorf("read base history: %w", err)
	}
	iterator, err := repository.Log(&git.LogOptions{From: head.Hash()})
	if err != nil {
		return sdk.GitContext{}, err
	}
	defer iterator.Close()
	err = iterator.ForEach(func(commit *object.Commit) error {
		if !excluded[commit.Hash] {
			context.CommitSubjects = append(context.CommitSubjects, sdk.Commit{SHA: commit.Hash.String(), Subject: commitSubject(commit.Message)})
		}
		return nil
	})
	if err != nil {
		return sdk.GitContext{}, err
	}
	return context, nil
}

func commitSet(repository *git.Repository, from plumbing.Hash) (map[plumbing.Hash]bool, error) {
	result := make(map[plumbing.Hash]bool)
	iterator, err := repository.Log(&git.LogOptions{From: from})
	if err != nil {
		return nil, err
	}
	defer iterator.Close()
	err = iterator.ForEach(func(commit *object.Commit) error {
		result[commit.Hash] = true
		return nil
	})
	return result, err
}

func openGoGit(root string) (*git.Repository, error) {
	return git.PlainOpenWithOptions(root, &git.PlainOpenOptions{EnableDotGitCommonDir: true})
}

func commitSubject(message string) string {
	return strings.TrimSpace(strings.SplitN(message, "\n", 2)[0])
}

func parseGitLog(output string) []sdk.Commit {
	parts := strings.Split(output, "\x00")
	commits := make([]sdk.Commit, 0, len(parts)/2)
	for i := 0; i+1 < len(parts); i += 2 {
		sha := strings.TrimSpace(parts[i])
		subject := strings.TrimSpace(parts[i+1])
		if sha != "" {
			commits = append(commits, sdk.Commit{SHA: sha, Subject: subject})
		}
	}
	return commits
}

func gitOutput(root string, args ...string) (string, error) {
	commandArgs := append([]string{"-C", root}, args...)
	output, err := exec.Command("git", commandArgs...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func GitPathDirty(root, path string) (bool, error) {
	command := exec.Command("git", "-C", root, "status", "--porcelain=v1", "--", path)
	output, commandErr := command.Output()
	if commandErr == nil {
		return len(bytes.TrimSpace(output)) > 0, nil
	}
	gitRoot, found := findGitRoot(root)
	if !found {
		return false, nil
	}
	repository, err := openGoGit(gitRoot)
	if err != nil {
		return false, fmt.Errorf("command: %v; fallback: %w", commandErr, err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		return false, fmt.Errorf("command: %v; fallback: %w", commandErr, err)
	}
	status, err := worktree.Status()
	if errors.Is(err, fs.ErrPermission) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("command: %v; fallback: %w", commandErr, err)
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return false, err
	}
	absolutePath := filepath.Join(absoluteRoot, filepath.FromSlash(path))
	relative, err := filepath.Rel(gitRoot, absolutePath)
	if err != nil {
		return false, err
	}
	entry, exists := status[filepath.ToSlash(relative)]
	if !exists {
		return false, nil
	}
	return entry.Staging != git.Unmodified || entry.Worktree != git.Unmodified, nil
}

func findGitRoot(root string) (string, bool) {
	current, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	for {
		if _, err := os.Lstat(filepath.Join(current, ".git")); err == nil {
			return current, true
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", false
		}
		current = parent
	}
}

func safePath(root, path string) (string, string, error) {
	return safepath.Existing(root, path)
}
