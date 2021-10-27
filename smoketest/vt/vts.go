package vt

import "encoding/xml"

type Parameter struct {
	ID      string `xml:"id,attr,omitempty"`
	Type    string `xml:"type,attr,omitempty"`
	Name    string `xml:"name,omitempty"`
	Default string `xml:"default,omitempty"`
}

type Reference struct {
	ID   string `xml:"id,attr,omitempty"`
	Type string `xml:"type,attr,omitempty"`
}

type Dependency struct {
	ID string `xml:"vt_id,attr,omitempty"`
}

type Solution struct {
	Type     string `xml:"type,attr,omitempty"`
	Method   string `xml:"method,attr,omitempty"`
	Solution string `xml:",chardata"`
}

type Detection struct {
	Type      string `xml:"qod_type,attr,omitempty"`
	Detection string `xml:",chardata"`
}

type Severity struct {
	Type   string `xml:"type,attr,omitempty"`
	Value  string `xml:"value,omitempty"`
	Origin string `xml:"origin,omitempty"`
	Date   int64  `xml:"date,omitempty"`
}

type Custom struct {
	Family           string `xml:"family,omitempty"`
	FileName         string `xml:"filename,omitempty"`
	RequiredKeys     string `xml:"required_keys,omitempty"`
	ExcludedKeys     string `xml:"excluded_keys,omitempty"`
	MandatoryKeys    string `xml:"mandatory_keys,omitempty"`
	CreationDate     string `xml:"creation_date,omitempty"`
	CvssBase         string `xml:"cvss_base,omitempty"`
	CvssBaseVector   string `xml:"cvss_base_vector,omitempty"`
	Deprecated       string `xml:"deprecated,omitempty"`
	LastModification string `xml:"last_modification,omitempty"`
	Qod              string `xml:"qod,omitempty"`
	QodType          string `xml:"qod_type,omitempty"`
	Vuldetect        string `xml:"vuldetect,omitempty"`
}

type VT struct {
	ID           string        `xml:"id,attr,omitempty"`
	Name         string        `xml:"name,omitempty"`
	Parameter    *[]Parameter  `xml:"params>param,omitempty"`
	References   *[]Reference  `xml:"refs>ref,omitempty"`
	Dependencies *[]Dependency `xml:"dependencies>dependency,omitempty"`
	Created      int64         `xml:"creation_time,omitempty"`
	Modified     int64         `xml:"modification_time,omitempty"`
	Summary      string        `xml:"summary,omitempty"`
	Impact       string        `xml:"impact,omitempty"`
	Affected     string        `xml:"affected,omitempty"`
	Insight      string        `xml:"insight,omitempty"`
	Solution     *Solution     `xml:"solution,omitempty"`
	Detection    *Detection    `xml:"detection,omitempty"`
	Severities   *[]Severity   `xml:"severities>severity,omitempty"`
	Custom       []Custom      `xml:"custom,omitempty"`
}

type VTs struct {
	Version string `xml:"vts_version,attr,omitempty"`
	Total   string `xml:"total,attr,omitempty"`
	Hash    string `xml:"sha256_hash,attr,omitempty"`
	VT      []VT   `xml:"vt,omitempty"`
}

type GetVTsResponse struct {
	Status     string `xml:"status,attr,omitempty"`
	StatusText string `xml:"status_text,attr,omitempty"`
	VTs        VTs    `xml:"vts,omitempty"`
}

type Get struct {
	XMLName xml.Name `xml:"get_vts"`
	ID      string   `xml:"vt_id,attr,omitempty"`
	Filter  string   `xml:"filter,attr,omitempty"`
	Details string   `xml:"details,attr,omitempty"`
}
