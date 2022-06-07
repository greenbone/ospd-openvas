package connection

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
)

var Debug = false

// SendCommand sends given cmd to OSP (protocol, address) and returns the response
func SendRaw(protocol, address string, cmd interface{}) ([]byte, error) {
	c, err := net.Dial(protocol, address)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	b, err := xml.Marshal(cmd)
	if err != nil {
		return nil, err
	}
	if Debug {
		fmt.Printf("request: %s\n", b)
	}
	n, err := c.Write(b)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, fmt.Errorf("%d bytes were not send", len(b)-n)
	}
	return io.ReadAll(c)
}

// SendCommand sends given cmd to OSP (protocol, address) and unmarshal the result into v
func SendCommand(protcol, address string, cmd, v interface{}) error {
	if reflect.ValueOf(v).Kind() != reflect.Ptr {
		return errors.New("non-pointer passed to Unmarshal")
	}
	incoming, err := SendRaw(protcol, address, cmd)
	if err != nil {
		return err
	}
	if Debug {
		fmt.Printf("response: %s\n", incoming)
	}
	if v == nil {
		return nil
	}
	return xml.Unmarshal(incoming, v)
}
