package shred

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Conf is a object containing all choices of the user
type Conf struct {
	Times  int
	Zeros  bool
	Remove bool
}

// Path shreds all files in the location of path
// recursively. If remove is set to true files will be deleted
// after shredding. When a file is shredded its content
// is NOT recoverable so USE WITH CAUTION!!!
func (conf Conf) Path(path string) error {
	stats, err := os.Stat(path)
	if err != nil {
		return err
	}

	if stats.IsDir() {
		return conf.dir(path)
	}

	return conf.file(path)
}

// Dir overwrites every File in the location of path and everything in its subdirectories
func (conf Conf) dir(path string) error {
	var chErrors []chan error
	dirs := []string{}

	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			dirs = append(dirs, path)
			return nil
		}

		chErr := make(chan error)
		chErrors = append(chErrors, chErr)
		go func() {
			err := conf.file(path)
			chErr <- err
		}()

		return nil
	}

	if err := filepath.Walk(path, walkFn); err != nil {
		return err
	}

	for _, chErr := range chErrors {
		if err := <-chErr; err != nil {
			return err
		}
	}
	if conf.Remove {
		sort.Sort(sort.Reverse(sort.StringSlice(dirs)))
		for _, dir := range dirs {
			if err := os.Remove(dir); err != nil {
				return fmt.Errorf("failed to remove %s: %w", dir, err)
			}
		}
	}

	return nil
}

// File overwrites a given File in the location of path
func (conf Conf) file(filePath string) error {

	if stat, err := os.Stat(filePath); err != nil {
		return err
	} else if !stat.Mode().IsRegular() {
		return fmt.Errorf("file %s is not a regular file", filePath)
	}

	for i := 0; i < conf.Times; i++ {
		if err := overwriteFile(filePath, true); err != nil {
			return err
		}
	}

	if conf.Zeros {
		if err := overwriteFile(filePath, false); err != nil {
			return err
		}
	}

	if conf.Remove {
		if err := os.Remove(filePath); err != nil {
			return err
		}
	}

	return nil
}

func overwriteFile(filePath string, random bool) error {
	f, err := os.OpenFile(filePath, os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	buff := make([]byte, info.Size())
	if random {
		if _, err := rand.Read(buff); err != nil {
			return err
		}
	}

	_, err = f.WriteAt(buff, 0)
	return err
}
