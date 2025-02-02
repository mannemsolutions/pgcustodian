package utils_test

import (
	"fmt"
	"mannemsolutions/pgcustodian/pkg/utils"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveHome(t *testing.T) {
	home, err := os.UserHomeDir()
	assert.NoError(t, err, "We should be able to resolve a normal homedir")
	assert.Equal(t, home, utils.ResolveHome("~/"), "simple homedir check")
	assert.Equal(t, fmt.Sprintf("%s/a", home), utils.ResolveHome("~/./a/b/c/../../"), "clean")
}

func TestMakeTree(t *testing.T) {
	// Create folder
	tmpDir, err := os.MkdirTemp("", "MakeTree")
	if err != nil {
		panic(fmt.Errorf("unable to create temp dir: %w", err))
	}

	// add file
	dirPath := filepath.Join(tmpDir, "a/b/c/d")
	err = utils.MakeTree(dirPath)
	assert.NoError(t, err, "should be able to create %s without issues", dirPath)
	assert.DirExists(t, dirPath, "%s should exist and be a directory")
}

func TestAbsolutePath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "AbsolutePath")
	if err != nil {
		panic(fmt.Errorf("unable to create temp dir: %w", err))
	}

	tmpDir, err = utils.AbsolutePath(tmpDir)
	assert.NoError(t, err, "should be able to resolve %s", tmpDir)

	filePath := filepath.Join(tmpDir, "file")
	t.Logf("writing %s to file %s", "some data", filePath)
	if err = os.WriteFile(filePath, []byte("some data"), 0o600); err != nil {
		panic(fmt.Errorf("unable to create %s temp file: %w", filePath, err))
	}

	linkDir := filepath.Join(tmpDir, "link")
	if err = os.Symlink(tmpDir, linkDir); err != nil {
		panic(fmt.Errorf("unable to symlink %s to %s: %w", linkDir, tmpDir, err))
	}
	for _, a := range []struct {
		input    string
		expected string
		isError  bool
	}{
		{linkDir, tmpDir, false},
		{tmpDir, tmpDir, false},
		{fmt.Sprintf("%s/link/link/link", linkDir), tmpDir, false},
		{fmt.Sprintf("%s/link/link/link/a/b/c", linkDir), fmt.Sprintf("%s/a/b/c", tmpDir), true},
		{fmt.Sprintf("%s/link/./../link/./link", linkDir), tmpDir, false},
		{fmt.Sprintf("%s/a/b/c/link/./link", linkDir), tmpDir, true},
	} {
		absPatch, err := utils.AbsolutePath(a.input)
		if a.isError {
			assert.Error(t, err, "should not be able to resolve %s to a absolute path")
			assert.Equal(t, "", absPatch, "%s should resolve to %s", a.expected, a.input)

		} else {
			assert.NoError(t, err, "should be able to resolve %s to a absolute path")
			assert.Equal(t, a.expected, absPatch, "%s should resolve to %s", a.expected, a.input)

		}
	}
}
