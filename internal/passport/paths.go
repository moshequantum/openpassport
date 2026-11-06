package passport

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrPathTraversal = errors.New("path traversal detected: path escapes base directory")
	ErrAbsolutePath  = errors.New("absolute paths are not permitted in passport entries")
)

// SafeJoin joins baseDir with an untrusted relative path and ensures that
// the resolved path remains strictly inside baseDir. It rejects ".." traversal,
// absolute paths, and external symlinks.
func SafeJoin(baseDir, untrustedPath string) (string, error) {
	if filepath.IsAbs(untrustedPath) || strings.HasPrefix(untrustedPath, "/") || strings.HasPrefix(untrustedPath, "\\") {
		return "", fmt.Errorf("%w: %q", ErrAbsolutePath, untrustedPath)
	}

	cleanRel := filepath.Clean(filepath.FromSlash(untrustedPath))
	if cleanRel == ".." || strings.HasPrefix(cleanRel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", ErrPathTraversal, untrustedPath)
	}

	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}

	target := filepath.Join(absBase, cleanRel)
	relToBase, err := filepath.Rel(absBase, target)
	if err != nil || relToBase == ".." || strings.HasPrefix(relToBase, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", ErrPathTraversal, untrustedPath)
	}

	// Verify symlinks if the target file/dir already exists
	if fi, err := os.Lstat(target); err == nil && (fi.Mode()&os.ModeSymlink != 0) {
		evaluated, err := filepath.EvalSymlinks(target)
		if err != nil {
			return "", err
		}
		symRel, err := filepath.Rel(absBase, evaluated)
		if err != nil || symRel == ".." || strings.HasPrefix(symRel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("%w (via symlink): %q points outside base directory", ErrPathTraversal, untrustedPath)
		}
	}

	return target, nil
}
