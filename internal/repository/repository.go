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
}

type Repository struct {
	root  string
	files []sdk.File
	git   sdk.GitContext
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
	repository := &Repository{root: absolute, files: files}
	repository.git = inspectGit(absolute, options)
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
	var matches []sdk.File
	for _, file := range r.files {
		included, err := matchesAny(file.Path, include)
		if err != nil {
			return nil, err
		}
		if !included {
			continue
		}
		excluded, err := matchesAny(file.Path, exclude)
		if err != nil {
			return nil, err
		}
		if !excluded {
			matches = append(matches, file)
		}
	}
	return matches, nil
}

func (r *Repository) Read(path string) (sdk.File, error) {
	clean, absolute, err := safePath(r.root, path)
	if err != nil {
		return sdk.File{}, err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return sdk.File{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return sdk.File{}, fmt.Errorf("%s: symbolic links are not read", clean)
	}
	if !info.Mode().IsRegular() {
		return sdk.File{}, fmt.Errorf("%s: not a regular file", clean)
	}
	data, err := os.ReadFile(absolute)
	if err != nil {
		return sdk.File{}, err
	}
	return sdk.File{Path: clean, Mode: info.Mode(), Data: data}, nil
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
	context.Branch = gitOutput(root, "branch", "--show-current")
	context.Commit = gitOutput(root, "rev-parse", "HEAD")
	context.Dirty = strings.TrimSpace(gitOutput(root, "status", "--porcelain=v1", "--untracked-files=normal")) != ""
	if options.BaseSHA != "" && context.Commit != "" {
		output := gitOutput(root, "log", "--format=%H%x00%s", "-z", options.BaseSHA+".."+context.Commit)
		parts := strings.Split(output, "\x00")
		for i := 0; i+1 < len(parts); i += 2 {
			sha := strings.TrimSpace(parts[i])
			subject := strings.TrimSpace(parts[i+1])
			if sha != "" {
				context.CommitSubjects = append(context.CommitSubjects, sdk.Commit{SHA: sha, Subject: subject})
			}
		}
	} else if context.Commit != "" {
		context.CommitSubjects = []sdk.Commit{{SHA: context.Commit, Subject: gitOutput(root, "show", "-s", "--format=%s", "HEAD")}}
	}
	return context
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
