package connection

import (
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
)

//TODO move this to smoketest
// OSPDSender sends given commands to OSPD
type OSPDSender interface {
	// SendCommand sends a given cmd and parses to result into given interface{}
	SendCommand(cmd, v interface{}) error
	// SendRaw sends a given cmd and returns the result in []bytes
	SendRaw(cmd interface{}) ([]byte, error)
}

// ospdCon represents the connection used to connect to OSPD
type ospdCon struct {
	Protocol string // The protocol to be used OSPD supports tcp with TLS and unix
	Address  string // Either a path to a unix socker or host:port combination
	CertPath string // Path to certificate used by OSPD when not UNIX socket, default: "/var/lib/gvm/CA/servercert.pem"
	KeyPath  string // Path to keyfile of certigicate used by OSPD when not UNIX socket, default: "/var/lib/gvm/private/CA/serverkey.pem"
	Debug    bool   // when true it will preint the send commands
}

// New creates a OSPDSender
func New(
	protocol string,
	address string,
	certPath string,
	keyPath string,
	debug bool,
) OSPDSender {
	return &ospdCon{protocol, address, certPath, keyPath, debug}
}

// SendCommand sends given cmd to OSP (protocol, address) and returns the response
func (con *ospdCon) SendRaw(cmd interface{}) ([]byte, error) {
	var c net.Conn
	var err error

	if con.Protocol == "tcp" {
		cer, err := tls.LoadX509KeyPair(con.CertPath, con.KeyPath)
		if err != nil {
			return nil, err
		}
		conf := &tls.Config{
			Certificates:       []tls.Certificate{cer},
			InsecureSkipVerify: true,
		}
		c, err = tls.Dial("tcp", con.Address, conf)
	} else {
		c, err = net.Dial(con.Protocol, con.Address)
	}
	if err != nil {
		return nil, err
	}
	defer c.Close()

	b, err := xml.Marshal(cmd)
	if err != nil {
		return nil, err
	}
	if con.Debug {
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
func (con *ospdCon) SendCommand(cmd, v interface{}) error {
	if reflect.ValueOf(v).Kind() != reflect.Ptr {
		return errors.New("non-pointer passed to Unmarshal")
	}
	incoming, err := con.SendRaw(cmd)
	if err != nil {
		return err
	}
	if con.Debug {
		fmt.Printf("response: %s\n", incoming)
	}
	if v == nil {
		return nil
	}
	return xml.Unmarshal(incoming, v)
}
