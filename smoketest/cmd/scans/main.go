package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/greenbone/ospd-openvas/smoketest/connection"
	"github.com/greenbone/ospd-openvas/smoketest/policies"
	"github.com/greenbone/ospd-openvas/smoketest/scan"
	"github.com/greenbone/ospd-openvas/smoketest/usecases"
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

	tps := flag.String("policies", "", "comma separated list of policies to use for a scan.")
	policyPath := flag.String("policy-path", "/usr/local/src/policies", "path to policies.")
	host := flag.String("host", "", "host to scan")
	oids := flag.String("oid", "", "comma separated list of oid of a plugin to execute")
	ports := flag.String("ports", "22,80,443,8080", "comma separated list of oid of a ports")
	username := flag.String("user", "", "user of host (when using credentials)")
	password := flag.String("password", "", "password of user (when using credentials)")
	scan_id := flag.String("id", "", "id of a scan")
	cmd := flag.String("cmd", "", "Can either be start,get,start-finish.")
	flag.Parse()
	tillFinished := false
	var ospdCMD interface{}
	if flag.Parsed() {
		switch *cmd {
		case "get":
			ospdCMD = scan.GetScans{
				ID: *scan_id,
			}
		case "start-finish":
			tillFinished = true
			fallthrough

		case "start":
			alive := scan.AliveTestMethods{
				ConsiderAlive: 1,
			}
			target := scan.Target{
				Hosts:            *host,
				Ports:            *ports,
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
			selection := scan.VTSelection{
				Single: make([]scan.VTSingle, 0),
				Group:  make([]scan.VTGroup, 0),
			}

			policyCache, err := policies.InitCache(*policyPath)
			if err != nil {
				panic(err)
			}
			if *tps != "" {
				for _, policy := range strings.Split(*tps, ",") {
					ps := policyCache.ByName(policy).AsVTSelection()
					selection.Group = append(selection.Group, ps.Group...)
					selection.Single = append(selection.Single, ps.Single...)
				}
			}
			if *oids != "" {
				for _, oid := range strings.Split(*oids, ",") {
					selection.Single = append(selection.Single, scan.VTSingle{
						ID: oid,
					})
				}
			}

			ospdCMD = scan.Start{
				Targets:       scan.Targets{Targets: []scan.Target{target}},
				VTSelection:   []scan.VTSelection{selection},
				ScannerParams: DefaultScannerParams,
			}

		default:
			flag.Usage()
			os.Exit(1)
		}
	}
	connection.Debug = false

	if !tillFinished {
		b, err := connection.SendRaw(protocoll, address, ospdCMD)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s\n", b)
	} else {

		resp := usecases.StartScanGetLastStatus(ospdCMD.(scan.Start), protocoll, address)
		if resp.Failure != nil {
			panic(fmt.Errorf(resp.Failure.Description))
		}
		for _, r := range resp.Resp.Scan.Results.Results {
			fmt.Printf("%+v\n", r)
		}
	}

}
