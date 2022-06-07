/*
This cmd is
  parsing the scan-configs,
  looking within a source dir for nvts with either oid or family
  to copy them to a target dir.

It is mainly used to prevent an unnecessarily large feed within the smoketest image when testing the policies.
*/
package main

import (
	"flag"
	"fmt"

	"github.com/greenbone/ospd-openvas/smoketest/feed"
	"github.com/greenbone/ospd-openvas/smoketest/nasl"
	"github.com/greenbone/ospd-openvas/smoketest/policies"
)

func main() {
	source := flag.String("s", "/var/lib/openvas/plugins", "A path to existing plugins to copy from.")
	target := flag.String("t", "", "A path to prepare the new plugins layout.")
	policy := flag.String("p", "", "Path to scan-configs / plugins.")
	flag.Parse()
	if *source == "" || *target == "" || *policy == "" {
		flag.Usage()
		return
	}
	fmt.Print("Initializing caches")
	naslCache, err := nasl.InitCache(*source)
	if err != nil {
		panic(err)
	}
	policyCache, err := policies.InitCache(*policy)
	if err != nil {
		panic(err)
	}
	policies := policyCache.Get()
	fmt.Printf(" found %d plugins and %d policies\n", len(naslCache.Get()), len(policies))
	p := feed.NewPreparer(naslCache, policyCache, *source, *target)
	fmt.Printf("Preparing feed structure %s\n", *target)
	if err := p.Run(); err != nil {
		panic(err)
	}
	p.Wait()

	fmt.Printf("Prepared feed structure %s\n", *target)
}
