package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/greenbone/ospd-openvas/smoketest/connection"
	"github.com/greenbone/ospd-openvas/smoketest/policies"
	"github.com/greenbone/ospd-openvas/smoketest/scan"
)

var address string

const protocoll = "unix"

func init() {
	address = os.Getenv("OSPD_SOCKET")
	if address == "" {
		address = "/var/run/ospd/ospd.sock"
	}
}

var DefaultScannerParams = []scan.ScannerParam{
	{},
}

func main() {

	policy := flag.String("policy", "", "policy to use for a scan.")
	policyPath := flag.String("policy-path", "/usr/local/src/policies", "path to policies.")
	host := flag.String("host", "", "host to scan")
	oids := flag.String("oid", "", "oid of a plugin to execute")
	username := flag.String("user", "", "user of host (when using credentials)")
	password := flag.String("password", "", "password of user (when using credentials)")
	scan_id := flag.String("id", "", "id of a scan")
	cmd := flag.String("cmd", "automatic", "get either be start,get,automatic. On automatic the cmd will be selected based on other parameter.")
	flag.Parse()
	var ospdCMD interface{}
	if flag.Parsed() {
		if *cmd == "automatic" {
			if *host == "" && *scan_id != "" {
				*cmd = "get"
			} else {
				*cmd = "start"
			}
		}
		switch *cmd {
		case "get":
			ospdCMD = scan.GetScans{
				ID: *scan_id,
			}
		case "start":
			alive := scan.AliveTestMethods{
				ConsiderAlive: 1,
			}
			target := scan.Target{
				Hosts:            *host,
				Ports:            "22,80,443,8080",
				AliveTestMethods: alive,
			}
			if *username != "" {
				credential := scan.Credential{
					Type:     "up",
					Service:  "ssh",
					Username: *username,
					Password: *password,
				}
				target.Credentials = scan.Credentials{
					Credentials: []scan.Credential{credential},
				}
			}
			var selection scan.VTSelection

			policyCache, err := policies.InitCache(*policyPath)
			if err != nil {
				panic(err)
			}
			selection = policyCache.ByName(*policy).AsVTSelection()
			if *oids != "" {
				selection.Single = append(selection.Single, scan.VTSingle{
					ID: *oids,
				})
			}

			ospdCMD = scan.Start{
				Targets:       scan.Targets{Targets: []scan.Target{target}},
				VTSelection:   []scan.VTSelection{selection},
				ScannerParams: DefaultScannerParams,
			}

		}
	}
	connection.Debug = true
	b, err := connection.SendRaw(protocoll, address, ospdCMD)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", b)
}
