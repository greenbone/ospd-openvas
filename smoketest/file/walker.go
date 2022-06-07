package file

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Walker struct {
	Suffix  string
	Handler func(*os.File) error
	wg      sync.WaitGroup
}

func (fw *Walker) Wait() {
	fw.wg.Wait()
}

func Retry(path string, fo func(string) (*os.File, error)) (*os.File, error) {

open:
	f, err := fo(path)
	if pe, ok := err.(*fs.PathError); ok {
		if pe.Err.Error() == "too many open files" {
			// wait for a bit and retry
			time.Sleep(1 * time.Second)
			goto open
		}
	}
	return f, err
}

func (fw *Walker) Walk(p string, i os.FileInfo, e error) error {
	if e != nil {
		if pe, ok := e.(*fs.PathError); i.IsDir() && ok {
			if pe.Err.Error() == "too many open files" {
				// wait for a bit and retry
				time.Sleep(1 * time.Second)
				return filepath.Walk(p, fw.Walk)
			}
		}
		panic(e)
	}
	if !i.IsDir() && strings.HasSuffix(p, fw.Suffix) {
		fw.wg.Add(1)
		go func(path string) {
			defer fw.wg.Done()

			f, err := Retry(path, os.Open)
			if err != nil {
				panic(err)
			}
			if err := fw.Handler(f); err != nil {
				panic(err)
			}
			f.Close()
		}(p)

	}
	return nil
}
