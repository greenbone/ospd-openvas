package scan

import (
	"fmt"

	"github.com/greenbone/ospd-openvas/smoketest/connection"
	"github.com/greenbone/ospd-openvas/smoketest/scan"
	"github.com/greenbone/ospd-openvas/smoketest/usecases"
)

var DefaultScannerParams = []scan.ScannerParam{
	{TableDrivenLSC: "0"},
}

var DefaultAlive = scan.AliveTestMethods{
	ConsiderAlive: 1,
}

var DefaultTargets = scan.Targets{Targets: []scan.Target{
	{
		Hosts:            "localhost,smoketest.localdomain,smoke.localdomain,and.localdomain,mirrors.localdomain",
		Ports:            "8080,443",
		AliveTestMethods: DefaultAlive,
	},
},
}

var DefaultSelection = []scan.VTSelection{
	{Single: []scan.VTSingle{{
		ID: "0.0.0.0.0.0.0.0.0.1",
	}}},
}
var DefaultStart = scan.Start{
	ScannerParams: DefaultScannerParams,
	Targets:       DefaultTargets,
	VTSelection:   DefaultSelection,
}

func ScanStatusFinished(status string) bool {
	switch status {
	case "interrupted", "finished", "stopped", "failed":
		return true
	default:
		return false
	}
}

type getScanResponseFailure struct {
	resp    scan.GetScansResponse
	failure *usecases.Response
}

func WrongScanStatus(expected, got string) *usecases.Response {
	return &usecases.Response{
		Success:     false,
		Description: fmt.Sprintf("Expected %s but got %s as a Scan.Status", expected, got),
	}

}

func VerifyGet(get scan.GetScans, proto, address, status string) getScanResponseFailure {
	var result getScanResponseFailure
	if err := connection.SendCommand(proto, address, get, &result.resp); err != nil {
		panic(err)
	}
	if result.resp.Code != "200" {
		result.failure = WrongStatusCodeResponse(result.resp.StatusCodeResponse)
		return result
	}
	if result.resp.Scan.Status != status {
		result.failure = WrongScanStatus(status, result.resp.Scan.Status)
	}
	return result
}

func VerifyTillNextState(get scan.GetScans, proto, address, status string) getScanResponseFailure {
	if r := VerifyGet(get, proto, address, status); r.failure != nil {
		return r
	}
	return TillNextState(get, proto, address, status)

}

func TillNextState(get scan.GetScans, proto, address, status string) getScanResponseFailure {
	var result getScanResponseFailure
	result.resp.Scan.Status = status
	for result.resp.Scan.Status == status {
		result.resp = scan.GetScansResponse{}
		if err := connection.SendCommand(proto, address, get, &result.resp); err != nil {
			panic(err)
		}
		if result.resp.Code != "200" {
			result.failure = WrongStatusCodeResponse(result.resp.StatusCodeResponse)
			break
		}
	}

	return result
}

func StartScanGetLastStatus(start scan.Start, proto, address string) getScanResponseFailure {
	var result getScanResponseFailure
	var startR scan.StartResponse

	if err := connection.SendCommand(proto, address, start, &startR); err != nil {
		panic(err)
	}
	if startR.Code != "200" {
		result.failure = WrongStatusCodeResponse(startR.StatusCodeResponse)
		return result
	}
	get := scan.GetScans{ID: startR.ID}

	for !ScanStatusFinished(result.resp.Scan.Status) {
		// reset to not contain previous results
		result.resp = scan.GetScansResponse{}
		if err := connection.SendCommand(proto, address, get, &result.resp); err != nil {
			panic(err)
		}
		if result.resp.Code != "200" {
			result.failure = WrongStatusCodeResponse(result.resp.StatusCodeResponse)
			return result
		}
	}
	return result

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
				return *WrongStatusCodeResponse(startR.StatusCodeResponse)
			}
			get := scan.GetScans{ID: startR.ID}

			if r := VerifyTillNextState(get, proto, address, "queued"); r.failure == nil {
				if r.resp.Scan.Status != "init" {
					return *WrongScanStatus("init", r.resp.Scan.Status)
				}
				r = TillNextState(get, proto, address, "init")
				if r.failure != nil {
					return *r.failure
				}
				if r.resp.Scan.Status != "running" {
					return *WrongScanStatus("running", r.resp.Scan.Status)
				}
				var stopR scan.StopResponse
				if err := connection.SendCommand(proto, address, scan.Stop{ID: get.ID}, &stopR); err != nil {
					panic(err)
				}
				if stopR.Code != "200" {
					return *WrongStatusCodeResponse(r.resp.StatusCodeResponse)
				}
				r = VerifyGet(get, proto, address, "stopped")
				if r.failure != nil {
					return *r.failure
				}

				var deleteR scan.DeleteResponse
				connection.SendCommand(proto, address, scan.Delete{ID: get.ID}, &deleteR)
				if deleteR.Code != "200" {
					return *WrongStatusCodeResponse(deleteR.StatusCodeResponse)
				}

				resume := DefaultStart
				resume.ID = get.ID
				r = StartScanGetLastStatus(resume, proto, address)
				if r.resp.Scan.Status != "finished" {
					return *WrongScanStatus("finished", r.resp.Scan.Status)
				}
			} else {
				return *r.failure
			}

			return usecases.Response{
				Success:     true,
				Description: "",
			}

		},
	}
}

func WrongStatusCodeResponse(response scan.StatusCodeResponse) *usecases.Response {
	return &usecases.Response{
		Success:     false,
		Description: fmt.Sprintf("Wrong status code(%s): %s", response.Code, response.Text),
	}
}

func startScan() usecases.Test {
	return usecases.Test{
		Title: "start",
		Run: func(proto, address string) usecases.Response {

			r := StartScanGetLastStatus(DefaultStart, proto, address)
			if r.resp.Scan.Status != "finished" {
				return *WrongScanStatus("finished", r.resp.Scan.Status)
			}
			return usecases.Response{
				Success: r.resp.Scan.Status == "finished",
				Description: fmt.Sprintf("Espected status of %s to be finished but was %s",
					r.resp.Scan.ID, r.resp.Scan.Status),
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
		},
	}
}
