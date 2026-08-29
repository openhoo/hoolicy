// Package packarchive implements Hoolicy's canonical, non-executable pack
// artifact. Archives are deterministic and reject links, devices, traversal,
// oversized content, and ambiguous duplicate paths.
package packarchive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/openhoo/hoolicy/internal/safepath"
)

const (
	MediaType      = "application/vnd.openhoo.hoolicy.pack.v1+tar+gzip"
	ArtifactType   = "application/vnd.openhoo.hoolicy.pack.v1"
	MaxFiles       = 1000
	MaxFileSize    = 2 << 20
	MaxArchiveSize = 10 << 20
	MaxTotalSize   = 20 << 20
)

const maxTarSize = MaxTotalSize + MaxArchiveSize

type archiveEntry struct {
	name string
	data []byte
}

func Build(root string) ([]byte, string, error) {
	entries, err := readPackEntries(root)
	if err != nil {
		return nil, "", err
	}
	return canonicalArchive(entries)
}

func readPackEntries(root string) ([]archiveEntry, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("pack root must be a real directory")
	}
	var names []string
	err = filepath.WalkDir(root, func(candidate string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, candidate)
		if err != nil {
			return err
		}
		if relative == ".git" && entry.IsDir() {
			return filepath.SkipDir
		}
		if relative == "." || entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("non-regular pack entry is forbidden: %s", filepath.ToSlash(relative))
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > MaxFileSize {
			return fmt.Errorf("pack file exceeds %d bytes: %s", MaxFileSize, filepath.ToSlash(relative))
		}
		names = append(names, filepath.ToSlash(relative))
		if len(names) > MaxFiles {
			return fmt.Errorf("pack exceeds %d files", MaxFiles)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	entries := make([]archiveEntry, 0, len(names))
	var total int64
	for _, name := range names {
		data, err := readPackFile(root, name)
		if err != nil {
			return nil, err
		}
		total += int64(len(data))
		if total > MaxTotalSize {
			return nil, fmt.Errorf("pack content exceeds %d bytes", MaxTotalSize)
		}
		entries = append(entries, archiveEntry{name: name, data: data})
	}
	return entries, nil
}

func readPackFile(root, name string) ([]byte, error) {
	_, absolute, err := safepath.Existing(root, name)
	if err != nil {
		return nil, err
	}
	pathInfo, err := os.Lstat(absolute)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("pack entry changed or is not regular: %s", name)
	}
	file, err := os.Open(absolute)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	currentInfo, pathErr := os.Lstat(absolute)
	if statErr != nil || pathErr != nil || currentInfo.Mode()&os.ModeSymlink != 0 || !opened.Mode().IsRegular() || !os.SameFile(opened, currentInfo) || opened.Size() > MaxFileSize {
		_ = file.Close()
		return nil, fmt.Errorf("pack entry changed or exceeds limits: %s", name)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, MaxFileSize+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(data) > MaxFileSize || int64(len(data)) != opened.Size() {
		return nil, fmt.Errorf("pack entry changed or exceeds limits: %s", name)
	}
	return data, nil
}

func canonicalArchive(entries []archiveEntry) ([]byte, string, error) {
	if len(entries) == 0 {
		return nil, "", errors.New("pack archive is empty")
	}
	if len(entries) > MaxFiles {
		return nil, "", fmt.Errorf("pack exceeds %d files", MaxFiles)
	}
	entries = append([]archiveEntry(nil), entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	var output bytes.Buffer
	gzipWriter, err := gzip.NewWriterLevel(&output, gzip.BestCompression)
	if err != nil {
		return nil, "", err
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	var total int64
	for index, entry := range entries {
		name, err := safeArchivePath(entry.name)
		if err != nil {
			return nil, "", err
		}
		if index > 0 && entries[index-1].name == name {
			return nil, "", fmt.Errorf("duplicate archive path %s", name)
		}
		if len(entry.data) > MaxFileSize {
			return nil, "", fmt.Errorf("pack file exceeds %d bytes: %s", MaxFileSize, name)
		}
		total += int64(len(entry.data))
		if total > MaxTotalSize {
			return nil, "", fmt.Errorf("pack content exceeds %d bytes", MaxTotalSize)
		}
		header := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(entry.data)), ModTime: time.Unix(0, 0).UTC(), AccessTime: time.Time{}, ChangeTime: time.Time{}, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tarWriter.WriteHeader(header); err != nil {
			return nil, "", err
		}
		if _, err := tarWriter.Write(entry.data); err != nil {
			return nil, "", err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return nil, "", err
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, "", err
	}
	if output.Len() > MaxArchiveSize {
		return nil, "", fmt.Errorf("pack archive exceeds %d bytes", MaxArchiveSize)
	}
	hash := sha256.Sum256(output.Bytes())
	return output.Bytes(), "sha256:" + hex.EncodeToString(hash[:]), nil
}

func Extract(data []byte, target string) (string, error) {
	if len(data) > MaxArchiveSize {
		return "", fmt.Errorf("pack archive exceeds %d bytes", MaxArchiveSize)
	}
	target, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	targetInfo, err := os.Lstat(target)
	if err != nil {
		return "", err
	}
	if targetInfo.Mode()&os.ModeSymlink != 0 || !targetInfo.IsDir() {
		return "", errors.New("pack extraction target must be a real directory")
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		return "", err
	}
	if len(entries) != 0 {
		return "", errors.New("pack extraction target must be empty")
	}
	archiveEntries, err := parseArchive(data)
	if err != nil {
		return "", err
	}
	canonical, digest, err := canonicalArchive(archiveEntries)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(canonical, data) {
		return "", errors.New("pack archive is not in canonical Hoolicy format")
	}
	for _, entry := range archiveEntries {
		if err := writeExtractedEntry(target, entry); err != nil {
			return "", err
		}
	}
	return digest, nil
}

func parseArchive(data []byte) ([]archiveEntry, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func() { _ = gzipReader.Close() }()
	limited := &io.LimitedReader{R: gzipReader, N: maxTarSize + 1}
	tarReader := tar.NewReader(limited)
	seen := make(map[string]bool)
	entries := make([]archiveEntry, 0)
	var total int64
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(entries) == MaxFiles {
			return nil, fmt.Errorf("pack exceeds %d files", MaxFiles)
		}
		name, err := safeArchivePath(header.Name)
		if err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate archive path %s", name)
		}
		seen[name] = true
		if header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("archive entry %s is not a regular file", name)
		}
		if header.Size < 0 || header.Size > MaxFileSize {
			return nil, fmt.Errorf("archive entry %s has invalid size", name)
		}
		total += header.Size
		if total > MaxTotalSize {
			return nil, fmt.Errorf("pack content exceeds %d bytes", MaxTotalSize)
		}
		body := make([]byte, int(header.Size))
		if _, err := io.ReadFull(tarReader, body); err != nil {
			return nil, fmt.Errorf("read archive entry %s: %w", name, err)
		}
		entries = append(entries, archiveEntry{name: name, data: body})
	}
	if len(entries) == 0 {
		return nil, errors.New("pack archive is empty")
	}
	if _, err := io.Copy(io.Discard, limited); err != nil {
		return nil, err
	}
	if limited.N == 0 {
		return nil, fmt.Errorf("pack tar stream exceeds %d bytes", maxTarSize)
	}
	return entries, nil
}

func writeExtractedEntry(target string, entry archiveEntry) error {
	destination := filepath.Join(target, filepath.FromSlash(entry.name))
	if !strings.HasPrefix(destination, filepath.Clean(target)+string(os.PathSeparator)) {
		return fmt.Errorf("archive entry escapes extraction target: %s", entry.name)
	}
	_, checkedDestination, err := safepath.Writable(target, entry.name)
	if err != nil {
		return err
	}
	if checkedDestination != destination {
		return fmt.Errorf("archive entry resolves ambiguously: %s", entry.name)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	if _, checked, err := safepath.Writable(target, entry.name); err != nil || checked != destination {
		return fmt.Errorf("unsafe extraction destination %s", entry.name)
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(entry.data)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if written != len(entry.data) {
		return io.ErrShortWrite
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}

func safeArchivePath(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '\x00') || strings.Contains(name, "\\") || path.IsAbs(name) || archiveWindowsVolume(name) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != name {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	return clean, nil
}

func archiveWindowsVolume(name string) bool {
	return len(name) >= 2 && name[1] == ':' && (name[0] >= 'A' && name[0] <= 'Z' || name[0] >= 'a' && name[0] <= 'z')
}
