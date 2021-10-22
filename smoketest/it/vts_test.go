package it

import (
	"os"
	"strings"
	"testing"

	"github.com/greenbone/ospd-openvas/smoketest/connection"
	"github.com/greenbone/ospd-openvas/smoketest/vt"
)

var address string
const protocoll = "unix"
const pluginPath = "../data/plugins"

func init() {
	address = os.Getenv("OSPD_SOCKET")
	if address == "" {
		address = "/var/run/ospd/ospd.sock"
	}
}

func TestGetVTs(t *testing.T) {
    var response vt.GetVTsResponse
    if err := connection.SendCommand(protocoll, address, vt.Get{}, &response); err != nil {
		t.Fatalf("Connectio to %s failed: %s", address, err)
    }
	n := 0
	dirs, err :=os.ReadDir(pluginPath)
	if err != nil {
		t.Fatalf("Plugin folder %s not found: %s", pluginPath, err)
	}
	for _, d := range dirs {
		if d.Type().IsRegular() {
			if strings.HasSuffix(d.Name(), ".nasl") {
				n = n + 1
			}
		}
	}
	if len(response.VTs.VT) != n {
		t.Errorf("Expected %d vts but got %d", n, len(response.VTs.VT))
	}
}
