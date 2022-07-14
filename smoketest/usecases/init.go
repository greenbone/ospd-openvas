package usecases

import (
	"fmt"

	"github.com/greenbone/ospd-openvas/smoketest/connection"
	"github.com/greenbone/ospd-openvas/smoketest/scan"
)

type Runner func(string, string) Response

type Test struct {
	Title string
	Run   Runner
}

type Response struct {
	Success     bool
	Description string
}

type Tests struct {
	Title    string
	UseCases []Test
}

func (ouc Tests) Run(proto, address string) []Response {
	result := make([]Response, len(ouc.UseCases))
	fmt.Printf("Testing %s\n", ouc.Title)
	for i, t := range ouc.UseCases {
		fmt.Printf("\t%s\t", t.Title)
		result[i] = t.Run(proto, address)
		if !result[i].Success {
			fmt.Printf("\x1B[31mX\x1B[0m\n")
		} else {
			fmt.Printf("\x1B[32m✓\x1B[0m\n")
		}
	}
	return result
}
func WrongStatusCodeResponse(response scan.StatusCodeResponse) *Response {
	return &Response{
		Success:     false,
		Description: fmt.Sprintf("Wrong status code(%s): %s", response.Code, response.Text),
	}
}

func WrongScanStatus(expected, got string) *Response {
	return &Response{
		Success:     false,
		Description: fmt.Sprintf("Expected %s but got %s as a Scan.Status", expected, got),
	}

}

func ScanStatusFinished(status string) bool {
	switch status {
	case "interrupted", "finished", "stopped", "failed":
		return true
	default:
		return false
	}
}

type GetScanResponseFailure struct {
	Resp    scan.GetScansResponse
	Failure *Response
}

func VerifyGet(get scan.GetScans, proto, address, status string) GetScanResponseFailure {
	var result GetScanResponseFailure
	if err := connection.SendCommand(proto, address, get, &result.Resp); err != nil {
		panic(err)
	}
	if result.Resp.Code != "200" {
		result.Failure = WrongStatusCodeResponse(result.Resp.StatusCodeResponse)
		return result
	}
	if result.Resp.Scan.Status != status {
		result.Failure = WrongScanStatus(status, result.Resp.Scan.Status)
	}
	return result
}

func VerifyTillNextState(get scan.GetScans, proto, address, status string) GetScanResponseFailure {
	if r := VerifyGet(get, proto, address, status); r.Failure != nil {
		return r
	}

	return TillNextState(get, proto, address, status)

}

func TillNextState(get scan.GetScans, proto, address, status string) GetScanResponseFailure {
	var result GetScanResponseFailure
	result.Resp.Scan.Status = status
	for result.Resp.Scan.Status == status {
		result.Resp = scan.GetScansResponse{}
		if err := connection.SendCommand(proto, address, get, &result.Resp); err != nil {
			panic(err)
		}
		if result.Resp.Code != "200" {
			result.Failure = WrongStatusCodeResponse(result.Resp.StatusCodeResponse)
			break
		}
	}

	return result
}

func TillState(get scan.GetScans, proto, address, status string) GetScanResponseFailure {
	var result GetScanResponseFailure
	result.Resp.Scan.Status = status
	for !ScanStatusFinished(result.Resp.Scan.Status) && result.Resp.Scan.Status != status {
		result.Resp = scan.GetScansResponse{}
		if err := connection.SendCommand(proto, address, get, &result.Resp); err != nil {
			panic(err)
		}
		if result.Resp.Code != "200" {
			result.Failure = WrongStatusCodeResponse(result.Resp.StatusCodeResponse)
			break
		}
	}
	if result.Failure == nil && result.Resp.Scan.Status != status {
		result.Failure = WrongScanStatus(status, result.Resp.Scan.Status)
	}

	return result
}

type MessageHandler interface {
	Each(scan.GetScansResponse)
	Last(scan.GetScansResponse)
}

func StartScanGetLastStatus(start scan.Start, proto, address string, mhs ...MessageHandler) GetScanResponseFailure {
	var result GetScanResponseFailure
	var startR scan.StartResponse

	if err := connection.SendCommand(proto, address, start, &startR); err != nil {
		panic(err)
	}
	if startR.Code != "200" {
		result.Failure = WrongStatusCodeResponse(startR.StatusCodeResponse)
		return result
	}
	get := scan.GetScans{ID: startR.ID}

	for !ScanStatusFinished(result.Resp.Scan.Status) {
		// reset to not contain previous results
		result.Resp = scan.GetScansResponse{}
		if err := connection.SendCommand(proto, address, get, &result.Resp); err != nil {
			panic(err)
		}
		for _, mh := range mhs {
			if mh != nil {
				mh.Each(result.Resp)
			}
		}
		if result.Resp.Code != "200" {
			result.Failure = WrongStatusCodeResponse(result.Resp.StatusCodeResponse)
			return result
		}
	}
	for _, mh := range mhs {
		if mh != nil {
			mh.Last(result.Resp)
		}
	}
	return result

}
