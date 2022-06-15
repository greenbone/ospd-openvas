package scan

import (
	"fmt"

	"github.com/greenbone/ospd-openvas/smoketest/connection"
	"github.com/greenbone/ospd-openvas/smoketest/scan"
	"github.com/greenbone/ospd-openvas/smoketest/usecases"
)

var DefaultTargets = scan.Targets{Targets: []scan.Target{
	{
		Hosts:            "localhost,smoketest.localdomain,smoke.localdomain,and.localdomain,mirrors.localdomain",
		Ports:            "8080,443",
		AliveTestMethods: scan.ConsiderAlive,
	},
},
}

var DefaultSelection = []scan.VTSelection{
	{Single: []scan.VTSingle{{
		ID: "0.0.0.0.0.0.0.0.0.1",
	}}},
}
var DefaultStart = scan.Start{
	ScannerParams: scan.DisableNotus,
	Targets:       DefaultTargets,
	VTSelection:   DefaultSelection,
}

func stopDeleteWhenNoResults() usecases.Test {
	return usecases.Test{
		Title: "When no results: Queue->Init->Running->Stop->Delete",
		Run: func(proto, address string) usecases.Response {
			testeach := scan.AliveTestMethods{
				ICMP:          1,
				TCPSYN:        1,
				TCPACK:        1,
				ARP:           1,
				ConsiderAlive: 0,
			}
			target := scan.Targets{Targets: []scan.Target{
				{
					Hosts:            "localhost,smoketest.localdomain,smoke.localdomain,and.localdomain,mirrors.localdomain",
					Ports:            "8080,443",
					AliveTestMethods: testeach,
				},
			},
			}
			slowSelection := []scan.VTSelection{
				{Single: []scan.VTSingle{{
					ID: "0.0.0.0.0.0.0.0.0.2",
				}}},
			}
			startScan := scan.Start{
				ScannerParams: scan.DefaultScannerParams,
				Targets:       target,
				VTSelection:   slowSelection,
			}

			var startR scan.StartResponse
			if err := connection.SendCommand(proto, address, startScan, &startR); err != nil {
				panic(err)
			}
			if startR.Code != "200" {
				return *usecases.WrongStatusCodeResponse(startR.StatusCodeResponse)
			}
			get := scan.GetScans{ID: startR.ID}

			r := usecases.TillState(get, proto, address, "running")
			if r.Failure != nil {
				return *r.Failure
			}
			if len(r.Resp.Scan.Results.Results) > 1 {
				return usecases.Response{
					Success:     false,
					Description: fmt.Sprintf("Expected to have 0 results but got %d", len(r.Resp.Scan.Results.Results)),
				}
			}

			var stopR scan.StopResponse
			if err := connection.SendCommand(proto, address, scan.Stop{ID: get.ID}, &stopR); err != nil {
				panic(err)
			}
			if stopR.Code != "200" {
				return *usecases.WrongStatusCodeResponse(r.Resp.StatusCodeResponse)
			}

			var deleteR scan.DeleteResponse
			connection.SendCommand(proto, address, scan.Delete{ID: get.ID}, &deleteR)
			if deleteR.Code != "200" {
				return *usecases.WrongStatusCodeResponse(deleteR.StatusCodeResponse)
			}

			return usecases.Response{
				Success:     true,
				Description: "",
			}

		},
	}
}

func transitionQueueToRunning() usecases.Test {
	return usecases.Test{
		Title: "GVMD Workflow: Queue->Init->Running->Stop->Delete-Start->Finish",
		Run: func(proto, address string) usecases.Response {
			var startR scan.StartResponse
			if err := connection.SendCommand(proto, address, DefaultStart, &startR); err != nil {
				panic(err)
			}
			if startR.Code != "200" {
				return *usecases.WrongStatusCodeResponse(startR.StatusCodeResponse)
			}
			get := scan.GetScans{ID: startR.ID}

			if r := usecases.VerifyTillNextState(get, proto, address, "queued"); r.Failure == nil {
				if r.Resp.Scan.Status != "init" {
					// on some slower machines it can happen that the call to get the state
					// is taking too long for the init phase and it is already running.
					// On this case we just skip forward.
					if r.Resp.Scan.Status == "running" {
						goto is_running
					}
					return *usecases.WrongScanStatus("init", r.Resp.Scan.Status)
				}
				r = usecases.TillNextState(get, proto, address, "init")
				if r.Failure != nil {
					return *r.Failure
				}
				if r.Resp.Scan.Status != "running" {
					return *usecases.WrongScanStatus("running", r.Resp.Scan.Status)
				}
			is_running:
				var stopR scan.StopResponse
				if err := connection.SendCommand(proto, address, scan.Stop{ID: get.ID}, &stopR); err != nil {
					panic(err)
				}
				if stopR.Code != "200" {
					return *usecases.WrongStatusCodeResponse(r.Resp.StatusCodeResponse)
				}
				r = usecases.VerifyGet(get, proto, address, "stopped")
				if r.Failure != nil {
					return *r.Failure
				}

				var deleteR scan.DeleteResponse
				connection.SendCommand(proto, address, scan.Delete{ID: get.ID}, &deleteR)
				if deleteR.Code != "200" {
					return *usecases.WrongStatusCodeResponse(deleteR.StatusCodeResponse)
				}

				resume := DefaultStart
				resume.ID = get.ID
				r = usecases.StartScanGetLastStatus(resume, proto, address)
				if r.Resp.Scan.Status != "finished" {
					return *usecases.WrongScanStatus("finished", r.Resp.Scan.Status)
				}
			} else {
				return *r.Failure
			}

			return usecases.Response{
				Success:     true,
				Description: "",
			}

		},
	}
}

func startScan() usecases.Test {
	return usecases.Test{
		Title: "start",
		Run: func(proto, address string) usecases.Response {

			r := usecases.StartScanGetLastStatus(DefaultStart, proto, address)
			if r.Resp.Scan.Status != "finished" {
				return *usecases.WrongScanStatus("finished", r.Resp.Scan.Status)
			}
			return usecases.Response{
				Success: r.Resp.Scan.Status == "finished",
				Description: fmt.Sprintf("Espected status of %s to be finished but was %s",
					r.Resp.Scan.ID, r.Resp.Scan.Status),
			}

		},
	}
}

func Create() usecases.Tests {
	return usecases.Tests{
		Title: "Scan",
		UseCases: []usecases.Test{
			startScan(),
			transitionQueueToRunning(),
			stopDeleteWhenNoResults(),
		},
	}
}
