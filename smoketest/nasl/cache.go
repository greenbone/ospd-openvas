package nasl

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/greenbone/ospd-openvas/smoketest/file"
)

type Cache struct {
	sync.RWMutex
	plugins  []Plugin
	byOID    map[string]*Plugin
	byFamily map[string][]*Plugin
	byPath   map[string]*Plugin
}

func NewCache() *Cache {
	return &Cache{
		plugins:  make([]Plugin, 0),
		byOID:    make(map[string]*Plugin),
		byFamily: make(map[string][]*Plugin),
		byPath:   make(map[string]*Plugin),
	}
}

func (c *Cache) Append(p Plugin) {
	c.Lock()
	c.plugins = append(c.plugins, p)
	// point to the copy of c.plugins instead of given instance
	// to make it a bit easier for the garbage collector to not
	// have to track of the original
	ptr := &c.plugins[len(c.plugins)-1]
	c.byOID[p.OID] = ptr
	c.byPath[p.Path] = ptr
	if p.Family != "" {
		fam := strings.ToLower(p.Family)
		if f, ok := c.byFamily[fam]; ok {
			c.byFamily[fam] = append(f, ptr)
		} else {
			c.byFamily[fam] = []*Plugin{ptr}
		}

	}
	// not using defer to speed things up
	c.Unlock()
}

func (c *Cache) Get() []Plugin {
	c.RLock()
	defer c.RUnlock()
	return c.plugins
}

func (c *Cache) ByOID(oid string) *Plugin {
	c.RLock()
	defer c.RUnlock()
	if r, ok := c.byOID[oid]; ok {
		return r
	}
	return nil
}

func (c *Cache) ByPath(path string) *Plugin {
	c.RLock()
	defer c.RUnlock()
	if r, ok := c.byPath[path]; ok {
		return r
	}
	return nil
}

func (c *Cache) ByFamily(family string) []*Plugin {
	c.RLock()
	defer c.RUnlock()
	if family == "" {
		result := make([]*Plugin, 0)
		for _, v := range c.byFamily {
			result = append(result, v...)
		}
		return result
	} else {
		if r, ok := c.byFamily[family]; ok {
			return r
		}

	}
	return []*Plugin{}
}

type CacheFileWalkerHandler struct {
	cache  *Cache
	source string
}

func (fwh *CacheFileWalkerHandler) fh(f *os.File) error {
	p := Parse(fwh.source, f.Name(), f)
	f.Close()
	fwh.cache.Append(p)
	return nil
}

func NewCacheFileWalker(source string, c *Cache) *file.Walker {
	fwh := &CacheFileWalkerHandler{
		source: source,
		cache:  c,
	}
	return &file.Walker{
		Handler: fwh.fh,
		Suffix:  ".nasl",
	}
}

func InitCache(source string) (cache *Cache, err error) {
	cache = NewCache()
	fw := NewCacheFileWalker(source, cache)
	err = filepath.Walk(source, fw.Walk)
	if err != nil {
		return
	}
	fw.Wait()
	return
}
