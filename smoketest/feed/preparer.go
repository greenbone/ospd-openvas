package feed

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/greenbone/ospd-openvas/smoketest/file"
	"github.com/greenbone/ospd-openvas/smoketest/nasl"
	"github.com/greenbone/ospd-openvas/smoketest/policies"
	"github.com/greenbone/ospd-openvas/smoketest/scan"
)

const familyPrefixLen int = len("family = \"")

func copyFile(source, target, fpath string) (int64, error) {
	npath := strings.Replace(fpath, source, target, 1)
	bdir := filepath.Dir(npath)
	if _, err := os.Stat(bdir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(bdir, 0740); err != nil {
			return 0, err
		}
	}
	fin, err := file.Retry(fpath, os.Open)
	if err != nil {
		return 0, err
	}
	fout, err := file.Retry(npath, os.Create)
	if err != nil {
		fin.Close()
		return 0, err
	}
	blen, err := io.Copy(fout, fin)
	fin.Close()
	fout.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to copy %s into %s: %s\n", fpath, npath, err)
		if err := os.Remove(npath); err != nil {
			fmt.Fprintf(os.Stderr, "failed to remove %s: %s\n", npath, err)
		}
	}
	return blen, err

}

type preparer struct {
	wg          sync.WaitGroup
	naslCache   *nasl.Cache
	policyCache *policies.Cache
	feedsource  string
	feedtarget  string
}

func NewPreparer(naslCache *nasl.Cache, policyCache *policies.Cache, source, target string) *preparer {
	return &preparer{
		naslCache:   naslCache,
		policyCache: policyCache,
		feedsource:  source,
		feedtarget:  target,
	}
}

func (p *preparer) feedInfo() error {
	fip := filepath.Join(p.feedtarget, "plugin_feed_info.inc")
	if _, err := os.Stat(p.feedtarget); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(p.feedtarget, 0740); err != nil {
			return err
		}
	}
	if _, err := os.Stat(fip); errors.Is(err, os.ErrNotExist) {
		fout, err := os.Create(fip)
		if err != nil {
			return err
		}
		fmt.Fprintf(fout, "PLUGIN_SET = \"%d\"\n", time.Now().UnixMilli())
		fmt.Fprintf(fout, "PLUGIN_FEED = \"%s\"\n", "Policy Plugins Only")
		fmt.Fprintf(fout, "FEED_VENDOR = \"%s\"\n", "Greenbone Networks GmbH")
		fmt.Fprintf(fout, "FEED_HOME = \"%s\"\n", "N/A")
		fmt.Fprintf(fout, "FEED_NAME = \"%s\"\n", "PPO")
		fout.Close()

	}
	return nil
}

func (p *preparer) copyPlugin(n *nasl.Plugin) error {

	if _, err := copyFile(p.feedsource, p.feedtarget, n.Path); err != nil {
		return err
	}
	for _, inc := range n.Plugins {

		if _, err := copyFile(p.feedsource, p.feedtarget, inc); err != nil {
			return err
		}
	}
	return nil

}

func (p *preparer) Run() error {
	policies := p.policyCache.Get()
	if err := p.feedInfo(); err != nil {
		return err
	}
	for _, policy := range policies {
		s := policy.AsVTSelection()
		p.wg.Add(1)
		go func(s []scan.VTSingle) {
			defer p.wg.Done()
			for _, i := range s {
				p.wg.Add(1)
				go func(oid string) {
					defer p.wg.Done()
					if n := p.naslCache.ByOID(oid); n != nil {
						if err := p.copyPlugin(n); err != nil {
							fmt.Fprintf(os.Stderr, "Unable to copy %s: %s\n", n.OID, err)
						}
					} else {
						fmt.Fprintf(os.Stderr, "%s not found\n", oid)
					}

				}(i.ID)
			}

		}(s.Single)
		p.wg.Add(1)
		go func(g []scan.VTGroup) {
			defer p.wg.Done()
			for _, i := range g {
				p.wg.Add(1)
				go func(filter string) {
					defer p.wg.Done()
					fam := strings.ToLower(filter[familyPrefixLen : len(filter)-1])
					for _, j := range p.naslCache.ByFamily(fam) {
						if err := p.copyPlugin(j); err != nil {
							fmt.Fprintf(os.Stderr, "Unable to copy %s: %s\n", j.OID, err)
						}
					}
				}(i.Filter)
			}
		}(s.Group)
	}
	return nil
}

func (p *preparer) Wait() {
	p.wg.Wait()
}
