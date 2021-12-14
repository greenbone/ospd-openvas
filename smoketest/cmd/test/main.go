package main

import (
	"fmt"
	"log"
	"os"

	"github.com/greenbone/ospd-openvas/smoketest/connection"
	"github.com/greenbone/ospd-openvas/smoketest/vt"
)

var address string

const protocoll = "unix"
const pluginPath = "../data/plugins"
const notusPath = "../data/notus/advisories"

var title = map[string]string{
	"1.3.6.1.4.1.25623.1.0.90022": "NOTUS: should be overriden in get_nvts",
	"1.3.6.1.4.1.25623.1.0.42":    "I am also here",
	"1.3.6.1.4.1.25623.0.0.1":     "keys",
}

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
	var response vt.GetVTsResponse
	if err := connection.SendCommand(protocoll, address, vt.Get{}, &response); err != nil {
        panic(err)
	}
	r := getVTs()
	for len(r.VTs.VT) == 0 {
		r = getVTs()
	}
	return r

}


func main() {
    log.Print("Trying to connect")
	response := retryUntilPluginsAreLoaded()
	n := len(title)
    log.Printf("Got %d vts", len(response.VTs.VT))
	if len(response.VTs.VT) != n {
		panic(fmt.Errorf("Expected %d vts but got %d", n, len(response.VTs.VT)))
	}
	for _, v := range response.VTs.VT {
		if title[v.ID] != v.Name {
			panic(fmt.Errorf("Expected %s title but got %s", title[v.ID], v.Name))

		}
	}
    log.Print("Success")

}
