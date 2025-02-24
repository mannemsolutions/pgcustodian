package shred_test

import (
	"fmt"
	"mannemsolutions/pgcustodian/pkg/shred"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	numFiles = 2
)

type Files map[string][]byte

func generateTestSet(t *testing.T, dir string) (files Files) {
	files = make(Files)
	for i := 0; i < numFiles; i++ {
		filePath := filepath.Join(dir, fmt.Sprintf("file%d", i))
		contents := []byte(fmt.Sprintf("this is file %d", i))
		t.Logf("generating file %s", filePath)
		err := os.WriteFile(filePath, contents, 0o600)
		files[filePath] = contents
		require.NoError(t, err, "should be able to create file")
	}
	return files
}

func TestTimes(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ShredTime")
	if err != nil {
		panic(fmt.Errorf("unable to create temp dir: %w", err))
	}
	defer os.RemoveAll(tmpDir)
	files := generateTestSet(t, tmpDir)

	conf := shred.Conf{}
	assert.Error(t, conf.Path(path.Join(tmpDir, "not_existing")))

	err = conf.Path(tmpDir)
	require.NoError(t, err, "conf.Path should succeed")
	for filePath, contents := range files {
		t.Logf("checking file %s", filePath)
		data, err := os.ReadFile(filePath)
		assert.NoError(t, err, "should still be able to read file")
		assert.Equal(t, data, contents, "contents should not be overwritten")
	}

	conf.Times = 1
	err = conf.Path(tmpDir)
	require.NoError(t, err, "conf.Path should succeed")
	for filePath, contents := range files {
		t.Logf("checking file %s", filePath)
		data, err := os.ReadFile(filePath)
		assert.NoError(t, err, "should still be able to read file")
		assert.NotEqual(t, data, contents, "contents should be overwritten")
	}
}

func allZero(s []byte) bool {
	for _, v := range s {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestZeros(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ShredZeroes")
	if err != nil {
		panic(fmt.Errorf("unable to create temp dir: %w", err))
	}
	defer os.RemoveAll(tmpDir)
	files := generateTestSet(t, tmpDir)

	conf := shred.Conf{}
	err = conf.Path(tmpDir)
	require.NoError(t, err, "conf.Path should succeed")
	for filePath, contents := range files {
		t.Logf("checking file %s", filePath)
		data, err := os.ReadFile(filePath)
		assert.NoError(t, err, "should still be able to read file")
		assert.Len(t, data, len(contents), "contents should be overwritten")
		assert.False(t, allZero(data), "contents should not be zeroed")
	}
	conf.Zeros = true
	err = conf.Path(tmpDir)
	require.NoError(t, err, "conf.Path should succeed")
	for filePath, contents := range files {
		t.Logf("checking file %s", filePath)
		data, err := os.ReadFile(filePath)
		assert.NoError(t, err, "should still be able to read file")
		assert.Len(t, data, len(contents), "contents should be same size")
		assert.True(t, allZero(data), "contents should be zeroed")
	}
}

func TestRemove(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ShredZeroes")
	if err != nil {
		panic(fmt.Errorf("unable to create temp dir: %w", err))
	}
	defer os.RemoveAll(tmpDir)
	files := generateTestSet(t, tmpDir)

	conf := shred.Conf{}
	err = conf.Path(tmpDir)
	require.NoError(t, err, "conf.Path should succeed")
	for filePath := range files {
		t.Logf("checking file %s", filePath)
		assert.FileExists(t, filePath)
	}
	conf.Remove = true
	err = conf.Path(tmpDir)
	require.NoError(t, err, "conf.Path should succeed")
	for filePath := range files {
		t.Logf("checking file %s", filePath)
		assert.NoFileExists(t, filePath)
	}
}

func TestSubDir(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ShredSubDir")
	if err != nil {
		panic(fmt.Errorf("unable to create temp dir: %w", err))
	}
	conf := shred.Conf{Remove: true}

	unreachableDir := path.Join(tmpDir, "unreachable")
	err = os.Mkdir(unreachableDir, 0o00)
	require.NoError(t, err)
	err = conf.Path(tmpDir)
	assert.Error(t, err)
	err = os.Remove(unreachableDir)
	require.NoError(t, err)

	subDir := path.Join(tmpDir, "subdir")
	err = os.Mkdir(subDir, 0o700)
	require.NoError(t, err)
	files := generateTestSet(t, subDir)
	err = conf.Path(tmpDir)
	require.NoError(t, err)
	for filePath := range files {
		t.Logf("checking file %s", filePath)
		assert.NoFileExists(t, filePath)
	}
	assert.NoDirExists(t, subDir)
	assert.NoDirExists(t, tmpDir)
}
func TestFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ShredFile")
	if err != nil {
		panic(fmt.Errorf("unable to create temp dir: %w", err))
	}
	defer os.RemoveAll(tmpDir)
	files := generateTestSet(t, tmpDir)
	conf := shred.Conf{Remove: true}
	for filePath := range files {
		err = conf.Path(filePath)
		require.NoError(t, err, "conf.File should succeed")
		t.Logf("checking file %s", filePath)
		assert.NoFileExists(t, filePath)
	}
}

func TestSymlink(t *testing.T) {
	sourceTmpDir, err := os.MkdirTemp("", "shredSymlinkSource")
	if err != nil {
		panic(fmt.Errorf("unable to create temp dir: %w", err))
	}
	defer os.RemoveAll(sourceTmpDir)

	destTmpDir, err := os.MkdirTemp("", "shredSymlinkDest")
	if err != nil {
		panic(fmt.Errorf("unable to create temp dir: %w", err))
	}
	defer os.RemoveAll(destTmpDir)

	dstFiles := generateTestSet(t, destTmpDir)
	var srcFiles = make(Files)
	for dstPath, contents := range dstFiles {
		name := path.Base(dstPath)
		srcPath := path.Join(sourceTmpDir, name)
		require.NoError(t, os.Symlink(dstPath, srcPath), "should be able to create symlink")
		srcFiles[srcPath] = contents
	}

	err = shred.Conf{Remove: true}.Path(sourceTmpDir)
	require.NoError(t, err, "conf.Path should succeed")
	for filePath := range srcFiles {
		t.Logf("checking file %s", filePath)
		assert.NoFileExists(t, filePath)
	}
	for filePath, contents := range dstFiles {
		t.Logf("checking file %s", filePath)
		data, err := os.ReadFile(filePath)
		assert.NoError(t, err, "should still be able to read file")
		assert.Equal(t, data, contents, "contents should not be overwritten")
	}
}
