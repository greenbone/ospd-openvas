// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/greenbone/ospd-openvas/smoketest/connection"
	"github.com/greenbone/ospd-openvas/smoketest/policies"
	"github.com/greenbone/ospd-openvas/smoketest/vt"

	"github.com/greenbone/ospd-openvas/smoketest/usecases"
	"github.com/greenbone/ospd-openvas/smoketest/usecases/notus"
	"github.com/greenbone/ospd-openvas/smoketest/usecases/policy"
	"github.com/greenbone/ospd-openvas/smoketest/usecases/scan"
)

var username string
var password string

const protocoll = "unix"

func init() {
	username = os.Getenv("USERNAME")
	if username == "" {
		username = "gvm"
	}
	password = os.Getenv("PASSWORD")
	if password == "" {
		password = "test"
	}
}

func getVTs(co connection.OSPDSender) vt.GetVTsResponse {
	var response vt.GetVTsResponse
	if err := co.SendCommand(vt.Get{}, &response); err != nil {
		panic(err)
	}
	return response

}

func retryUntilPluginsAreLoaded(co connection.OSPDSender) vt.GetVTsResponse {
	r := getVTs(co)
	for len(r.VTs.VT) == 0 {
		r = getVTs(co)
	}
	return r

}

func PrintFailures(uc usecases.Tests, resp []usecases.Response) {
	hasFailures := false
	for i, r := range resp {
		if !r.Success {
			if !hasFailures {
				fmt.Printf("%s Failures:\n", uc.Title)
				hasFailures = true
			}
			fmt.Printf("\t%s:\n\t\t%s\n", uc.UseCases[i].Title, r.Description)
		}
	}
}

func main() {
	ospdSocket := flag.String("u", "/run/ospd/ospd-openvas.sock", "(optional, default: /run/ospd/ospd-openvas.sock) path the ospd unix socket")
	tcpAddress := flag.String("a", "", "(optional, when set it will NOT use unix socket but TCP) a target address (e.g. 10.42.0.81:4242)")
	policyPath := flag.String("policy-path", "/usr/local/src/policies", "(optional, default: /usr/local/src/policies) path to policies.")
	certPath := flag.String("cert-path", "", "(only require when port is set ) path to the certificate used by ospd.")
	certKeyPath := flag.String("certkey-path", "", "(only required when port is set) path to certificate key used by ospd.")
	tg := flag.String("t", "", "(optional) Name of testgroup. If set it just tests given testgroup t.")

	flag.Parse()
	fmt.Printf("Initializing policy cache (%s)\n", *policyPath)
	policyCache, err := policies.InitCache(*policyPath)
	if err != nil {
		panic(err)
	}
	protocoll := "unix"
	address := *ospdSocket
	if *tcpAddress != "" {
		protocoll = "tcp"
		address = *tcpAddress
	}

	co := connection.New(protocoll, address, *certPath, *certKeyPath, false)
	fmt.Print("Trying to connect\n")
	response := retryUntilPluginsAreLoaded(co)
	ucs := []usecases.Tests{
		notus.Create(username, password),
		scan.Create(),
		policy.Create(policyCache, username, password),
	}
	resps := make([][]usecases.Response, len(ucs))
	fmt.Printf("OSPD loaded %d vts\n", len(response.VTs.VT))
	for i, t := range ucs {
		if *tg == "" || *tg == t.Title {

			resps[i] = t.Run(co)
		}
	}
	for i, t := range ucs {
		PrintFailures(t, resps[i])
	}
}
