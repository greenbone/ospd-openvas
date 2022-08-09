package mqtt

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/eclipse/paho.golang/paho"
)

// TopicData is a tuple for Topic and Message.
type TopicData struct {
	Topic   string
	Message []byte
}

// MQTT is connection type for
type MQTT struct {
	client            *paho.Client
	connectProperties *paho.Connect
	qos               byte
	incoming          chan *TopicData // Is used to send respons messages of a handler downwards
}

func (m MQTT) Incoming() <-chan *TopicData {
	return m.incoming
}

func (m MQTT) Close() error {
	close(m.incoming)
	return m.client.Disconnect(&paho.Disconnect{ReasonCode: 0})
}

func (m MQTT) register(topic string) error {

	m.client.Router.RegisterHandler(topic, func(p *paho.Publish) {
		m.incoming <- &TopicData{Topic: topic, Message: p.Payload}

	})

	_, err := m.client.Subscribe(context.Background(), &paho.Subscribe{
		// we need NoLocal otherwise we would consum our own messages
		// again and ack them.
		Subscriptions: map[string]paho.SubscribeOptions{
			topic: {QoS: m.qos, NoLocal: true},
		},
	},
	)
	return err
}

func (m MQTT) Subscribe(topics ...string) error {
	for _, t := range topics {
		if err := m.register(t); err != nil {
			return err
		}
	}
	return nil
}

func (m MQTT) Publish(topic string, message interface{}) error {
	b, err := json.Marshal(message)
	if err != nil {
		return err
	}
	props := &paho.PublishProperties{}
	pb := &paho.Publish{
		Topic:      topic,
		QoS:        m.qos,
		Payload:    b,
		Properties: props,
	}
	_, err = m.client.Publish(context.Background(), pb)
	return err
}

func (m MQTT) Connect() error {
	ca, err := m.client.Connect(context.Background(), m.connectProperties)
	if err != nil {
		return err
	}
	if ca.ReasonCode != 0 {
		return fmt.Errorf(
			"failed to connect to %s : %d - %s",
			m.client.Conn.RemoteAddr().String(),
			ca.ReasonCode,
			ca.Properties.ReasonString,
		)
	}
	return nil
}

// Configuration holds information for MQTT
type Configuration struct {
	ClientID      string // The ID to be used when connecting to a broker
	Username      string // Username to be used as authentication; empty for anonymous
	Password      string // Password to be used as authentication with Username
	CleanStart    bool   // CleanStart when false and SessionExpiry set to > 1 it will reuse a session
	SessionExpiry uint64 // Amount of seconds a session is valid; WARNING when set to 0 it is effectively a cleanstart.
	QOS           byte
	KeepAlive     uint16
	Inflight      uint
}

func New(conn net.Conn,
	cfg Configuration,
) (*MQTT, error) {

	c := paho.NewClient(paho.ClientConfig{
		Router: paho.NewStandardRouter(),
		Conn:   conn,
	})

	cp := &paho.Connect{
		KeepAlive:  cfg.KeepAlive,
		ClientID:   cfg.ClientID,
		CleanStart: cfg.CleanStart,
		Username:   cfg.Username,
		Password:   []byte(cfg.Password),
	}
	if cfg.Username != "" {
		cp.UsernameFlag = true
	}
	if cfg.Password != "" {
		cp.PasswordFlag = true
	}

	return &MQTT{
		client:            c,
		connectProperties: cp,
		qos:               cfg.QOS,
		incoming:          make(chan *TopicData, cfg.Inflight),
	}, nil
}
