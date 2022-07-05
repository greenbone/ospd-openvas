package policy

import (
	"fmt"

	"github.com/greenbone/ospd-openvas/smoketest/policies"
	"github.com/greenbone/ospd-openvas/smoketest/scan"
	uc "github.com/greenbone/ospd-openvas/smoketest/usecases"
)

func discoveryAuthenticated(cache *policies.Cache, username, password string) uc.Test {
	return uc.Test{
		Title: "Discovery - enable authenticated checks",
		Run: func(proto string, address string) uc.Response {
			pol := "Discovery"
			sc := cache.ByName(pol)
			selection := sc.AsVTSelection(nil)
			if len(selection.Single) == 0 && len(selection.Group) == 0 {
				return uc.Response{
					Success:     false,
					Description: fmt.Sprintf("Config %s not found\n", pol),
				}
			}

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

			ospdCMD := scan.Start{
				Targets:       scan.Targets{Targets: []scan.Target{target}},
				VTSelection:   []scan.VTSelection{selection},
				ScannerParams: scan.DisableNotus,
			}
			r := uc.StartScanGetLastStatus(ospdCMD, proto, address)
			if r.Failure != nil {
				return *r.Failure
			}
			ssh_success_msg := "It was possible to login using the provided SSH credentials. Hence authenticated checks are enabled.\n"

			for _, rs := range r.Resp.Scan.Results.Results {
				if rs.Value == ssh_success_msg {
					return uc.Response{
						Success:     true,
						Description: "ssh login with given credentials was successful.",
					}
				}
			}

			return uc.Response{
				Success:     false,
				Description: "failed to find ssh success message",
			}
		},
	}
}
func Create(cache *policies.Cache, username, password string) uc.Tests {
	return uc.Tests{
		Title: "Policy/Scan-Config",
		UseCases: []uc.Test{
			discoveryAuthenticated(cache, username, password),
		},
	}
}
