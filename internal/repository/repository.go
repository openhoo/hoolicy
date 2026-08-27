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
		repository.git = inspectGit(absolute, options)
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

func inspectGit(root string, options Options) sdk.GitContext {
	context := sdk.GitContext{MergeRequestTitle: options.MergeRequestTitle, Properties: make(map[string]any)}
	status := gitOutput(root, "status", "--porcelain=v2", "--branch", "--untracked-files=normal")
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
		context.CommitSubjects = parseGitLog(gitOutput(root, "log", "--format=%H%x00%s", "-z", options.BaseSHA+".."+context.Commit))
	} else if context.Commit != "" {
		context.CommitSubjects = parseGitLog(gitOutput(root, "log", "-1", "--format=%H%x00%s", "-z", "HEAD"))
	}
	return context
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

func gitOutput(root string, args ...string) string {
	commandArgs := append([]string{"-C", root}, args...)
	output, err := exec.Command("git", commandArgs...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func safePath(root, path string) (string, string, error) {
	return safepath.Existing(root, path)
}
