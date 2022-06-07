package scan

import "encoding/xml"

type ScannerParam struct {
	TargetPort     string `xml:"target_port,omitempty"`
	UseHttps       int    `xml:"use_https,omitempty"`
	Profile        string `xml:"profile,omitempty"`
	TableDrivenLSC string `xml:"table_driven_lsc,omitempty"`
}

var DefaultScannerParams = []ScannerParam{
	{},
}

var DisableNotus = []ScannerParam{
	{TableDrivenLSC: "0"},
}

type VTValue struct {
	ID    string `xml:"id,attr,omitempty"`
	Value string `xml:",chardata"`
}

type VTSingle struct {
	ID     string    `xml:"id,attr,omitempty"`
	Values []VTValue `xml:"vt_value,omitempty"`
}

type VTGroup struct {
	Filter string `xml:"filter,attr,omitempty"`
}

type VTSelection struct {
	Single []VTSingle `xml:"vt_single,omitempty"`
	Group  []VTGroup  `xml:"vt_group,omitempty"`
}

type Credential struct {
	Type     string `xml:"type,attr,omitempty"`
	Service  string `xml:"service,attr,omitempty"`
	Port     string `xml:"port,attr,omitempty"`
	Username string `xml:"username,omitempty"`
	Password string `xml:"password,omitempty"`
}

type Credentials struct {
	XMLName     xml.Name     `xml:"credentials"`
	Credentials []Credential `xml:"credential"`
}

type AliveTestMethods struct {
	ICMP          int `xml:"icmp,omitempty"`
	TCPSYN        int `xml:"tcp_syn,omitempty"`
	TCPACK        int `xml:"tcp_ack,omitempty"`
	ARP           int `xml:"arp,omitempty"`
	ConsiderAlive int `xml:"consider_alive,omitempty"`
}

var ConsiderAlive AliveTestMethods = AliveTestMethods{
	ConsiderAlive: 1,
}

type Target struct {
	XMLName            xml.Name         `xml:"target"`
	Hosts              string           `xml:"hosts,omitempty"`
	Ports              string           `xml:"ports,omitempty"`
	Credentials        Credentials      `xml:"credentials,omitempty"`
	ExcludedHosts      string           `xml:"excluded_hosts,omitempty"`
	FinishedHosts      string           `xml:"finished_hosts,omitempty"`
	AliveTestPorts     string           `xml:"alive_test_ports,omitempty"`
	AliveTest          int              `xml:"alive_test,omitempty"`
	AliveTestMethods   AliveTestMethods `xml:"alive_test_methods,omitempty"`
	ReverseLookupUnify bool             `xml:"reverse_lookup_unify,omitempty"`
	ReverseLookupOnly  bool             `xml:"reverse_lookup_only,omitempty"`
}

type Targets struct {
	XMLName xml.Name `xml:"targets"`
	Targets []Target
}

type Start struct {
	XMLName       xml.Name       `xml:"start_scan"`
	Target        string         `xml:"target,attr,omitempty"`
	Ports         string         `xml:"ports,attr,omitempty"`
	ID            string         `xml:"scan_id,attr,omitempty"`
	Parallel      int            `xml:"parallel,attr,omitempty"`
	ScannerParams []ScannerParam `xml:"scanner_params"`
	VTSelection   []VTSelection  `xml:"vt_selection,omitempty"`
	Targets       Targets        `xml:"targets"`
}

type StatusCodeResponse struct {
	Text string `xml:"status_text,attr,omitempty"`
	Code string `xml:"status,attr,omitempty"`
}

type StartResponse struct {
	XMLName xml.Name `xml:"start_scan_response"`
	ID      string   `xml:"id,omitempty"`
	StatusCodeResponse
}

type Delete struct {
	XMLName xml.Name `xml:"delete_scan"`
	ID      string   `xml:"scan_id,attr,omitempty"`
}

type DeleteResponse struct {
	XMLName xml.Name `xml:"delete_scan_response"`
	StatusCodeResponse
}

type Stop struct {
	XMLName xml.Name `xml:"stop_scan"`
	ID      string   `xml:"scan_id,attr,omitempty"`
}

type StopResponse struct {
	XMLName xml.Name `xml:"stop_scan_response"`
	StatusCodeResponse
}

type GetScans struct {
	XMLName    xml.Name `xml:"get_scans"`
	ID         string   `xml:"scan_id,attr,omitempty"`
	Details    bool     `xml:"details,attr,omitempty"`
	Progress   bool     `xml:"progress,attr,omitempty"`
	PopResults bool     `xml:"pop_results,attr,omitempty"`
	MaxResults int      `xml:"max_results,attr,omitempty"`
}

type Result struct {
	Host     string `xml:"host,attr,omitempty"`
	HostName string `xml:"hostname,attr,omitempty"`
	Severity string `xml:"severity,attr,omitempty"`
	QOD      string `xml:"qod,attr,omitempty"`
	Port     string `xml:"port,attr,omitempty"`
	TestID   string `xml:"test_id,attr,omitempty"`
	Name     string `xml:"name,attr,omitempty"`
	Type     string `xml:"type,attr,omitempty"`
	Value    string `xml:",chardata"`
}

type Results struct {
	Results []Result `xml:"result,omitempty"`
}

type Scan struct {
	ID        string  `xml:"id,attr"`
	Target    string  `xml:"target,attr"`
	StartTime string  `xml:"start_time,attr"`
	EndTime   string  `xml:"end_time,attr"`
	Progress  int     `xml:"progress,attr"`
	Status    string  `xml:"status,attr"`
	Results   Results `xml:"results,omitempty"`
}

type GetScansResponse struct {
	XMLName xml.Name `xml:"get_scans_response"`
	StatusCodeResponse
	Scan Scan `xml:"scan"`
}
