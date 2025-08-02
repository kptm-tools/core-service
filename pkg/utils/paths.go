package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// FindProjectRoot attempts to find the project root directory by looking for go.mod
// It first tries to find it relative to the calling source file, then falls back
// to the current working directory.
func FindProjectRoot() (string, error) {
	// Get the path of the calling source file (skip 1 frame to get caller)
	_, filename, _, ok := runtime.Caller(1)
	if !ok {
		return "", fmt.Errorf("failed to get caller file path")
	}

	// Navigate up from the source file to find project root
	dir := filepath.Dir(filename)

	// Try different levels to find go.mod (indicator of project root)
	for i := 0; i < 10; i++ {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root
			break
		}
		dir = parent
	}

	// If go.mod not found via source file, fall back to current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}

	// Check if we're already in the project root
	if _, err := os.Stat(filepath.Join(cwd, "go.mod")); err == nil {
		return cwd, nil
	}

	// Try going up from current directory
	dir = cwd
	for i := 0; i < 5; i++ {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("could not find project root (no go.mod found)")
}
