package policies

import (
	"encoding/xml"
	"fmt"

	"github.com/greenbone/ospd-openvas/smoketest/nasl"
	"github.com/greenbone/ospd-openvas/smoketest/scan"
)

type NVTSelector struct {
	Include int    `xml:"include"`
	Type    int    `xml:"type"` // 0 = Disabled, 1 = Family, 2 = NVT
	Filter  string `xml:"family_or_nvt"`
}

type NVTSelectors struct {
	XMLName   xml.Name      `xml:"nvt_selectors"`
	Selectors []NVTSelector `xml:"nvt_selector"`
}

func (s NVTSelector) AsScanSelector(cache *nasl.Cache) (group *scan.VTGroup, single []scan.VTSingle) {
	switch s.Type {
	case 0:
		if cache != nil {

			plugins := cache.ByFamily("")
			single = make([]scan.VTSingle, len(plugins))
			for i, p := range plugins {
				single[i] = scan.VTSingle{
					ID: p.OID,
				}
			}
		}
	case 1:
		group = &scan.VTGroup{
			Filter: fmt.Sprintf("family = \"%s\"", s.Filter),
		}
	case 2:
		single = make([]scan.VTSingle, 1)
		single[0] = scan.VTSingle{
			ID: s.Filter,
		}
	}
	return
}

type ScanConfig struct {
	XMLName   xml.Name `xml:"config"`
	ID        string   `xml:"id,attr"`
	Name      string   `xml:"name"`
	Comment   string   `xml:"comment"`
	Type      int      `xml:"type"`       // no function since we just are a ospd scanner
	Usage     string   `xml:"usage_type"` // no function, we don't differntiate between policy and scan
	Selectors NVTSelectors
}

func (c ScanConfig) AsVTSelection(cache *nasl.Cache) scan.VTSelection {
	selection := scan.VTSelection{
		Single: make([]scan.VTSingle, 0),
		Group:  make([]scan.VTGroup, 0),
	}
	for _, sel := range c.Selectors.Selectors {
		g, s := sel.AsScanSelector(cache)
		if s != nil {
			selection.Single = append(selection.Single, s...)
		}
		if g != nil {
			selection.Group = append(selection.Group, *g)
		}

	}
	return selection
}
