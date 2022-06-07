package policies

import (
	"encoding/xml"
	"fmt"

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

func (s NVTSelector) AsScanSelector() (group *scan.VTGroup, single *scan.VTSingle) {
	if s.Type == 1 {
		group = &scan.VTGroup{
			Filter: fmt.Sprintf("family = \"%s\"", s.Filter),
		}
	}
	if s.Type == 2 {
		single = &scan.VTSingle{
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

func (c ScanConfig) AsVTSelection() scan.VTSelection {
	selection := scan.VTSelection{
		Single: make([]scan.VTSingle, 0),
		Group:  make([]scan.VTGroup, 0),
	}
	for _, sel := range c.Selectors.Selectors {
		if g, s := sel.AsScanSelector(); s != nil {
			selection.Single = append(selection.Single, *s)
		} else if g != nil {
			selection.Group = append(selection.Group, *g)
		}

	}
	return selection
}
