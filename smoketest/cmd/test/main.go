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

var ospdSocket string
var policyPath string
var username string
var password string

const protocoll = "unix"

func init() {
	ospdSocket = os.Getenv("OSPD_SOCKET")
	if ospdSocket == "" {
		ospdSocket = "/var/run/ospd/ospd.sock"
	}
	policyPath = os.Getenv("POLICY_PATH")
	if policyPath == "" {
		policyPath = "/usr/local/src/policies"
	}
	username = os.Getenv("USERNAME")
	if username == "" {
		username = "gvm"
	}
	password = os.Getenv("PASSWORD")
	if password == "" {
		password = "test"
	}
}

func getVTs() vt.GetVTsResponse {
	var response vt.GetVTsResponse
	if err := connection.SendCommand(protocoll, ospdSocket, vt.Get{}, &response); err != nil {
		panic(err)
	}
	return response

}

func retryUntilPluginsAreLoaded() vt.GetVTsResponse {
	r := getVTs()
	for len(r.VTs.VT) == 0 {
		r = getVTs()
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
	fmt.Printf("Initializing policy cache (%s)\n", policyPath)
	tg := flag.String("t", "", "Name of testgroup. If set it just tests given testgroup t.")
	flag.Parse()
	policyCache, err := policies.InitCache(policyPath)
	if err != nil {
		panic(err)
	}
	fmt.Print("Trying to connect\n")
	response := retryUntilPluginsAreLoaded()
	ucs := []usecases.Tests{
		notus.Create(username, password),
		scan.Create(),
		policy.Create(policyCache, username, password),
	}
	resps := make([][]usecases.Response, len(ucs))
	fmt.Printf("OSPD loaded %d vts\n", len(response.VTs.VT))
	for i, t := range ucs {
		if *tg == "" || *tg == t.Title {

			resps[i] = t.Run(protocoll, ospdSocket)
		}
	}
	for i, t := range ucs {
		PrintFailures(t, resps[i])
	}
}
