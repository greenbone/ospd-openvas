/*
Package notus is testing ospd-openvas functionality specific to enable notus.
*/
package notus

import (
	"fmt"

	"github.com/greenbone/ospd-openvas/smoketest/connection"
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

func Create() uc.Tests {
	return uc.Tests{
		Title: "Notus",
		UseCases: []uc.Test{
			includeNotusAdvisory(),
			overridesNVTS(),
		},
	}
}
