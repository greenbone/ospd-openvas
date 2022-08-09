package policies

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/greenbone/ospd-openvas/smoketest/file"
)

type Cache struct {
	cache map[string]ScanConfig
	sync.RWMutex
}

func (c *Cache) Append(s ScanConfig) {
	c.Lock()

	c.cache[strings.ToLower(s.Name)] = s
	c.Unlock()
}

func (c *Cache) Get() []ScanConfig {
	c.RLock()
	defer c.RUnlock()
	i := 0
	r := make([]ScanConfig, len(c.cache))
	for _, v := range c.cache {
		r[i] = v
		i++
	}
	return r
}

func (c *Cache) ByName(name string) ScanConfig {
	c.RLock()
	defer c.RUnlock()
	if s, ok := c.cache[strings.ToLower(name)]; ok {
		return s
	}
	return ScanConfig{}
}

func NewCache() *Cache {
	return &Cache{
		cache: make(map[string]ScanConfig),
	}
}

type FileWalkerHandler struct {
	cache *Cache
}

func (fw *FileWalkerHandler) fh(f *os.File) error {
	d := xml.NewDecoder(f)
	var sp ScanConfig
	if err := d.Decode(&sp); err != nil {
		return err
	}
	f.Close()
	fw.cache.Append(sp)
	return nil
}

func NewFileWalker(cache *Cache) *file.Walker {
	h := &FileWalkerHandler{
		cache: cache,
	}
	return &file.Walker{
		Handler: h.fh,
		Suffix:  ".xml",
	}
}

func InitCache(source string) (cache *Cache, err error) {
	cache = NewCache()
	fw := NewFileWalker(cache)
	err = filepath.Walk(source, fw.Walk)
	if err != nil {
		return
	}
	fw.Wait()
	return
}
