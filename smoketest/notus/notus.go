package notus

type Severity struct {
	Origin string `json:"origin"`
	Date   int64  `json:"date"`
	CVSSV2 string `json:"cvss_v2"`
	CVSSV3 string `json:"cvss_v3"`
}

type Advisory struct {
	OID              string   `json:"oid"`
	Title            string   `json:"title"`
	CreationDate     int64    `json:"creation_date"`
	LastModification int64    `json:"last_modification"`
	AdvisoryId       string   `json:"advisory_id"`
	AdvisoryXref     string   `json:"advisory_xref"`
	Cves             []string `json:"cves"`
	Summary          string   `json:"summary"`
	Insight          string   `json:"insight"`
	Affected         string   `json:"affected"`
	Impact           string   `json:"impact"`
	Xrefs            []string `json:"xrefs"`
	Severity         Severity `json:"seveerity"`
}

type Advisories struct {
	Version    string     `json:"version"`
	Advisories []Advisory `json:"advisories"`
}
