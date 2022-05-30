package main

import (
	"fmt"
	"os"

	"github.com/greenbone/ospd-openvas/smoketest/connection"
	"github.com/greenbone/ospd-openvas/smoketest/vt"

	"github.com/greenbone/ospd-openvas/smoketest/usecases"
	"github.com/greenbone/ospd-openvas/smoketest/usecases/notus"
	"github.com/greenbone/ospd-openvas/smoketest/usecases/scan"
)

var address string

const protocoll = "unix"

func init() {
	address = os.Getenv("OSPD_SOCKET")
	if address == "" {
		address = "/var/run/ospd/ospd.sock"
	}
}

func getVTs() vt.GetVTsResponse {
	var response vt.GetVTsResponse
	if err := connection.SendCommand(protocoll, address, vt.Get{}, &response); err != nil {
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
	fmt.Print("Trying to connect\n")
	response := retryUntilPluginsAreLoaded()
	ucs := []usecases.Tests{
		notus.Create(),
		scan.Create(),
	}
	resps := make([][]usecases.Response, len(ucs))
	fmt.Printf("OSPD loaded %d vts\n", len(response.VTs.VT))
	for i, t := range ucs {
		resps[i] = t.Run(protocoll, address)
	}
	for i, t := range ucs {
		PrintFailures(t, resps[i])
	}
}
