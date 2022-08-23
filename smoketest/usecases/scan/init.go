package scan

import (
	"fmt"

	"github.com/greenbone/ospd-openvas/smoketest/connection"
	"github.com/greenbone/ospd-openvas/smoketest/scan"
	"github.com/greenbone/ospd-openvas/smoketest/usecases"
)

var DefaultTargets = Targets(scan.ConsiderAlive)

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

func Targets(alive scan.AliveTestMethods) scan.Targets {
	return scan.Targets{Targets: []scan.Target{
		{
			Hosts:            "localhost,smoketest.localdomain,smoke.localdomain,and.localdomain,mirrors.localdomain",
			Ports:            "8080,443",
			AliveTestMethods: alive,
		},
	},
	}
}

func addHostName() usecases.Test {
	return usecases.Test{
		Title: "Add Host Name Function",
		Run: func(o connection.OSPDSender) usecases.Response {
			target := Targets(scan.Alive)
			slowSelection := []scan.VTSelection{
				{Single: []scan.VTSingle{{
					ID: "0.0.0.0.0.0.0.0.0.3",
				}}},
			}
			startScan := scan.Start{
				ScannerParams: scan.DefaultScannerParams,
				Targets:       target,
				VTSelection:   slowSelection,
			}
			r := usecases.StartScanGetLastStatus(startScan, o)
			if r.Resp.Scan.Status != "finished" {
				return *usecases.WrongScanStatus("finished", r.Resp.Scan.Status)
			}
			for _, result := range r.Resp.Scan.Results.Results {
				if result.HostName == "addhostname.localdomain" {
					return usecases.Response{
						Success: true,
					}
				}
			}
			return usecases.Response{
				Description: fmt.Sprintf("addhost not found in %+v", r.Resp.Scan.Results.Results),
				Success:     false,
			}

		},
	}
}

func stopDeleteWhenNoResults() usecases.Test {
	return usecases.Test{
		Title: "When no results: Queue->Init->Running->Stop->Delete",
		Run: func(co connection.OSPDSender) usecases.Response {
			target := Targets(scan.Alive)
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
			if err := co.SendCommand(startScan, &startR); err != nil {
				panic(err)
			}
			if startR.Code != "200" {
				return *usecases.WrongStatusCodeResponse(startR.StatusCodeResponse)
			}
			get := scan.GetScans{ID: startR.ID}

			r := usecases.TillState(get, co, "running")
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
			if err := co.SendCommand(scan.Stop{ID: get.ID}, &stopR); err != nil {
				panic(err)
			}
			if stopR.Code != "200" {
				return *usecases.WrongStatusCodeResponse(r.Resp.StatusCodeResponse)
			}

			var deleteR scan.DeleteResponse
			co.SendCommand(scan.Delete{ID: get.ID}, &deleteR)
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
		Run: func(co connection.OSPDSender) usecases.Response {
			var startR scan.StartResponse
			if err := co.SendCommand(DefaultStart, &startR); err != nil {
				panic(err)
			}
			if startR.Code != "200" {
				return *usecases.WrongStatusCodeResponse(startR.StatusCodeResponse)
			}
			get := scan.GetScans{ID: startR.ID}

			if r := usecases.VerifyTillNextState(get, co, "queued"); r.Failure == nil {
				if r.Resp.Scan.Status != "init" {
					// on some slower machines it can happen that the call to get the state
					// is taking too long for the init phase and it is already running.
					// On this case we just skip forward.
					if r.Resp.Scan.Status == "running" {
						goto is_running
					}
					return *usecases.WrongScanStatus("init", r.Resp.Scan.Status)
				}
				r = usecases.TillNextState(get, co, "init")
				if r.Failure != nil {
					return *r.Failure
				}
				if r.Resp.Scan.Status != "running" {
					return *usecases.WrongScanStatus("running", r.Resp.Scan.Status)
				}
			is_running:
				var stopR scan.StopResponse
				if err := co.SendCommand(scan.Stop{ID: get.ID}, &stopR); err != nil {
					panic(err)
				}
				if stopR.Code != "200" {
					return *usecases.WrongStatusCodeResponse(r.Resp.StatusCodeResponse)
				}
				r = usecases.VerifyGet(get, co, "stopped")
				if r.Failure != nil {
					return *r.Failure
				}

				var deleteR scan.DeleteResponse
				co.SendCommand(scan.Delete{ID: get.ID}, &deleteR)
				if deleteR.Code != "200" {
					return *usecases.WrongStatusCodeResponse(deleteR.StatusCodeResponse)
				}

				resume := DefaultStart
				resume.ID = get.ID
				r = usecases.StartScanGetLastStatus(resume, co)
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
		Run: func(co connection.OSPDSender) usecases.Response {

			r := usecases.StartScanGetLastStatus(DefaultStart, co)
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
			addHostName(),
			startScan(),
			transitionQueueToRunning(),
			stopDeleteWhenNoResults(),
		},
	}
}
