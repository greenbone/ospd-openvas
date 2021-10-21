package connection

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
)

// SendCommand sends given cmd to OSP (protocol, address) and unmarshal the result into v
func SendCommand(protcol, address string, cmd interface{}, v interface{}) error {
	if reflect.ValueOf(v).Kind() != reflect.Ptr {
		return errors.New("non-pointer passed to Unmarshal")
	}
    c, err := net.Dial(protcol, address)
    if err != nil {
        return err
    }
    defer c.Close()
    b, err := xml.Marshal(cmd)
    if err != nil {
        return err
    }
    n, err := c.Write(b)
    if err != nil {
        return err
    }
    if n != len(b) {
        return fmt.Errorf("%d bytes were not send", len(b) - n)
    }
    incoming, err := io.ReadAll(c)
    if err != nil {
        return err
    }
    return xml.Unmarshal(incoming, v)
}

