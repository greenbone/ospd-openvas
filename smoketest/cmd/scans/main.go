// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/greenbone/ospd-openvas/smoketest/connection"
	"github.com/greenbone/ospd-openvas/smoketest/nasl"
	"github.com/greenbone/ospd-openvas/smoketest/policies"
	"github.com/greenbone/ospd-openvas/smoketest/scan"
	"github.com/greenbone/ospd-openvas/smoketest/usecases"
)

var DefaultScannerParams = []scan.ScannerParam{
	{},
}

type PrintResponses struct{}

func (pr PrintResponses) Each(r scan.GetScansResponse) {
	fmt.Printf("\rprogress: %d", r.Scan.Progress)
}

func (pr PrintResponses) Last(r scan.GetScansResponse) {
	xr, err := xml.MarshalIndent(r, "", " ")
	if err != nil {
		panic(err)
	}
	tmp, err := ioutil.TempFile(os.TempDir(), fmt.Sprintf("result-%s.xml", r.Scan.ID))
	if tmp == nil {
		panic(err)
	}
	fmt.Printf("\rprogress: %d; status: %s; report: %s\n", r.Scan.Progress, r.Scan.Status, tmp.Name())
	if _, err := tmp.Write(xr); err != nil {
		panic(err)
	}
	tmp.Close()
}

func main() {

	vtDIR := flag.String("vt-dir", "/var/lib/openvas/plugins", "A path to existing plugins.")
	tps := flag.String("policies", "", "comma separated list of policies.")
	policyPath := flag.String("policy-path", "/usr/local/src/policies", "path to policies.")
	host := flag.String("host", "", "host to scan")
	oids := flag.String("oid", "", "comma separated list of oid of a plugin to execute")
	ports := flag.String("ports", "22,80,443,8080,513", "comma separated list of ports.")
	username := flag.String("user", "", "user of host (when using credentials)")
	password := flag.String("password", "", "password of user (when using credentials)")
	scan_id := flag.String("id", "", "id of a scan")
	alivemethod := flag.Int("alive-method", 15, "which alive method to use; 1. bit is for ICMP, 2. bit is for TCPSYN, 3. bit is for TCPACK, 4. bit is for ARP and 5. bit is to consider alive. Use 16 to disable alive check.")
	cmd := flag.String("cmd", "", "Can either be start,get,start-finish.")

	ospdSocket := flag.String("u", "/run/ospd/ospd-openvas.sock", "path the ospd unix socket")
	tcpAddress := flag.String("a", "", "(optional) a target address, will set usage from UNIX to TCP protocoll (e.g. 10.42.0.81:4242)")
	certPath := flag.String("cert-path", "", "(only required when 'a' is set ) path to the certificate used by ospd.")
	certKeyPath := flag.String("certkey-path", "", "(only required when 'a' is set) path to certificate key used by ospd.")

	debug := flag.Bool("v", false, "Enables or disables verbose.")
	flag.Parse()
	tillFinished := false
	naslCache, err := nasl.InitCache(*vtDIR)
	if err != nil {
		panic(err)
	}
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
				ICMP:          *alivemethod >> 0 & 1,
				TCPSYN:        *alivemethod >> 1 & 1,
				TCPACK:        *alivemethod >> 2 & 1,
				ARP:           *alivemethod >> 3 & 1,
				ConsiderAlive: *alivemethod >> 4 & 1,
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
					ps := policyCache.ByName(policy).AsVTSelection(naslCache)
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

	protocoll := "unix"
	address := *ospdSocket
	if *tcpAddress != "" {
		address = *tcpAddress
		protocoll = "tcp"
	}

	co := connection.New(protocoll, address, *certPath, *certKeyPath, *debug)

	if !tillFinished {
		b, err := co.SendRaw(ospdCMD)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s\n", b)
	} else {
		resp := usecases.StartScanGetLastStatus(ospdCMD.(scan.Start), co, PrintResponses{})
		if resp.Failure != nil {
			panic(fmt.Errorf(resp.Failure.Description))
		}
	}

}
