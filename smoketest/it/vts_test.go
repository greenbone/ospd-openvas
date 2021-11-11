package it

import (
	"os"
	"testing"

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

func getVTs(t *testing.T) vt.GetVTsResponse {
	var response vt.GetVTsResponse
	if err := connection.SendCommand(protocoll, address, vt.Get{}, &response); err != nil {
		t.Fatalf("Connectio to %s failed: %s", address, err)
	}
	return response

}

func retryUntilPluginsAreLoaded(t *testing.T) vt.GetVTsResponse {
	var response vt.GetVTsResponse
	if err := connection.SendCommand(protocoll, address, vt.Get{}, &response); err != nil {
		t.Fatalf("Connectio to %s failed: %s", address, err)
	}
	r := getVTs(t)
	for len(r.VTs.VT) == 0 {
		r = getVTs(t)
	}
	return r

}

func TestGetVTs(t *testing.T) {
	response := retryUntilPluginsAreLoaded(t)
	n := len(title)
	if len(response.VTs.VT) != n {
		t.Errorf("Expected %d vts but got %d", n, len(response.VTs.VT))
	}
	for _, v := range response.VTs.VT {
		if title[v.ID] != v.Name {
			t.Errorf("Expected %s title but got %s", title[v.ID], v.Name)

		}

	}
}
