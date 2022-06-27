package notus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/greenbone/ospd-openvas/smoketest/mqtt"
)

type Message struct {
	MessageId string `json:"message_id"`   //UUID(data.get("message_id")),
	GroupId   string `json:"group_id"`     //data.get("group_id"),
	Created   int64  `json:"created"`      //datetime.fromtimestamp(
	Type      string `json:"message_type"` //result.scan
}

func newMessage() Message {
	return Message{
		MessageId: uuid.NewString(),
		GroupId:   uuid.NewString(),
		Created:   time.Now().Unix(),
		Type:      "result.scan",
	}
}

type ScanStartMessage struct {
	MessageType string   `json:"message_type"`
	ID          string   `json:"scan_id"`
	HostIP      string   `json:"host_ip"`
	HostName    string   `json:"host_name"`
	OSRelease   string   `json:"os_release"`
	PackageList []string `json:"package_list"`
}

type ScanStatusMessage struct {
	ID     string `json:"scan_id"`
	Host   string `json:"host_ip"`
	Status string `json:"status"`
}

type ScanResultMessage struct {
	Message
	ID         string `json:"scan_id"`
	HostIP     string `json:"host_ip"`
	HostName   string `json:"host_name"`
	OID        string `json:"oid"`
	Value      string `json:"value"`
	Port       string `json:"port"`
	Uri        string `json:"uri"`
	ResultType string `json:"result_type"` // ALARM
}

func (s *Server) check() bool {

	select {
	case in, open := <-s.client.Incoming():
		if in != nil {
			var start ScanStartMessage
			if err := json.NewDecoder(bytes.NewReader(in.Message)).Decode(&start); err != nil {
				fmt.Fprintf(os.Stderr, "Unable to parse %s to ScanStartMessage: %s", string(in.Message), err)
				return open
			}
			running := ScanStatusMessage{
				ID:     start.ID,
				Host:   start.HostIP,
				Status: "running",
			}
			s.client.Publish("scanner/status", running)
			vulr := fmt.Sprintf("Vulnerable package: %s\nInstalled version: %s\nFixed version: %s\n", "a", "0.0.1", "0.0.2")
			resultMSG := ScanResultMessage{
				Message:    newMessage(),
				ID:         start.ID,
				HostIP:     start.HostIP,
				HostName:   start.HostName,
				OID:        "1.3.6.1.4.1.25623.1.0.90022",
				Value:      vulr,
				Port:       "package",
				Uri:        "",
				ResultType: "ALARM",
			}
			s.client.Publish("scanner/scan/info", resultMSG)
			running.Status = "finished"
			s.client.Publish("scanner/status", running)
			return open

		}
	}
	return false

}

// Server simulates a notus instance
type Server struct {
	address string
	client  *mqtt.MQTT
}

func NewServer(address string) (*Server, error) {
	conn, err := net.Dial("tcp", address)

	if err != nil {
		return nil, err
	}
	cfg := mqtt.Configuration{}
	client, err := mqtt.New(conn, cfg)
	if err != nil {
		return nil, err
	}

	return &Server{
		client:  client,
		address: address,
	}, nil
}

func (s *Server) Connect() error {
	if err := s.client.Connect(); err != nil {
		return err
	}
	if err := s.client.Subscribe("scanner/package/cmd/notus"); err != nil {
		return err
	}
	go func() {
		for s.check() {
			// keep running
		}
	}()
	return nil
}

func (s *Server) Close() error {
	return s.client.Close()
}
