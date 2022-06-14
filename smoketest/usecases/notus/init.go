/*
Package notus is testing ospd-openvas functionality specific to enable notus.
*/
package notus

import (
	"fmt"
	"strings"

	"github.com/greenbone/ospd-openvas/smoketest/connection"
	"github.com/greenbone/ospd-openvas/smoketest/scan"
	uc "github.com/greenbone/ospd-openvas/smoketest/usecases"
	"github.com/greenbone/ospd-openvas/smoketest/vt"
)

func includeNotusAdvisory() uc.Test {
	oid := "1.3.6.1.4.1.25623.1.0.42"
	return uc.Test{
		Title: "Advisories are included within GetVTs",
		Run: func(proto string, address string) uc.Response {
			var response vt.GetVTsResponse
			if err := connection.SendCommand(proto, address, vt.Get{
				ID: oid,
			}, &response); err != nil {
				panic(err)
			}
			return uc.Response{
				Success:     len(response.VTs.VT) == 1,
				Description: fmt.Sprintf("Expected to find %s once but found %d times", oid, len(response.VTs.VT)),
			}
		},
	}
}

func overridesNVTS() uc.Test {
	return uc.Test{
		Title: "Advisories override NASL",
		Run: func(proto string, address string) uc.Response {
			oid := "1.3.6.1.4.1.25623.1.0.90022"
			var response vt.GetVTsResponse
			expected := "NOTUS: should be overriden in get_nvts"
			if err := connection.SendCommand(proto, address, vt.Get{
				ID: oid,
			}, &response); err != nil {
				panic(err)
			}
			if len(response.VTs.VT) != 1 {
				return uc.Response{
					Success:     false,
					Description: fmt.Sprintf("Expected to find '%s' once but found %d times", oid, len(response.VTs.VT)),
				}
			}
			return uc.Response{
				Success:     response.VTs.VT[0].Name == expected,
				Description: fmt.Sprintf("Expected '%s' to be '%s'", response.VTs.VT[0].Name, expected),
			}

		},
	}
}

func containNotusResults(username, password string) uc.Test {
	return uc.Test{
		Title: "contain results",
		Run: func(proto, address string) uc.Response {
			oid := "1.3.6.1.4.1.25623.1.0.50282" // gatherpackagelist is a dependency for notus
			selection := scan.VTSelection{
				Single: []scan.VTSingle{{
					ID: oid,
				},
				},
			}
			s, err := NewServer("localhost:1883")
			if err != nil {
				return uc.Response{
					Description: err.Error(),
					Success:     false,
				}
			}
			if err = s.Connect(); err != nil {
				return uc.Response{
					Description: err.Error(),
					Success:     false,
				}
			}
			defer s.Close()

			credential := scan.Credential{
				Type:     "up",
				Service:  "ssh",
				Username: username,
				Password: password,
			}
			target := scan.Target{
				Hosts:            "localhost",
				Ports:            "22",
				AliveTestMethods: scan.ConsiderAlive,
				Credentials:      scan.Credentials{Credentials: []scan.Credential{credential}},
			}

			start := scan.Start{
				Targets:       scan.Targets{Targets: []scan.Target{target}},
				VTSelection:   []scan.VTSelection{selection},
				ScannerParams: scan.DefaultScannerParams,
			}
			resp := uc.StartScanGetLastStatus(start, proto, address)
			if resp.Failure != nil {
				return *resp.Failure
			}
			var msg string
			for _, r := range resp.Resp.Scan.Results.Results {
				if strings.HasPrefix(r.Value, "Vulnerable package") {

					return uc.Response{
						Description: fmt.Sprintf("results contained Notus result: %s", r.Value),
						Success:     true,
					}
				}
				msg = fmt.Sprintf("%s,%s", r.Value, msg)
			}

			return uc.Response{
				Description: fmt.Sprintf("no indicator for Notus results found in: %s\n", msg),
				Success:     false,
			}

		},
	}
}

func Create(user, pass string) uc.Tests {
	return uc.Tests{
		Title: "Notus",
		UseCases: []uc.Test{
			includeNotusAdvisory(),
			overridesNVTS(),
			containNotusResults(user, pass),
		},
	}
}
