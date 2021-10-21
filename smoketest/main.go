package main

import (
	"encoding/xml"
	"fmt"

	"github.com/greenbone/ospd-openvas/smoketest/vt"
	"github.com/greenbone/ospd-openvas/smoketest/connection"
)

func main(){
    
    var response vt.GetVTsResponse
    if err := connection.SendCommand("unix", "/tmp/ospd.sock", vt.Get{}, &response); err != nil {
        panic(err)
    }
    s, _ := xml.MarshalIndent(response, "", " ")
    fmt.Printf("read:\n%s\n", s)
}
