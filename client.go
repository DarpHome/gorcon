package gorcon

import (
	"encoding/binary"
	"errors"
	"net"
)

const (
	RequestIDStart int32 = 6516583
)

var (
	MCEndian           binary.ByteOrder = binary.LittleEndian
	ErrInvalidPassword error            = errors.New("invalid RCON password")
	counter            int32            = 0
)

type RCONClient struct {
	Address    string
	RequestID  int32
	Connection net.Conn
}

func NewRCONClient() *RCONClient {
	counter++
	return &RCONClient{
		RequestID: RequestIDStart + counter - 1,
	}
}

func (client *RCONClient) SendPacket(packet Packet) error {
	_, err := WritePacket(client.Connection, packet)
	return err
}

func (client *RCONClient) RecvPacket() (*Packet, error) {
	return ReadPacket(client.Connection)
}

func (client *RCONClient) Connect(address string) error {
	connection, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}
	client.Connection = connection
	client.Address = address
	return nil
}

func (client *RCONClient) Login(password string) error {
	if err := client.SendPacket(Packet{
		RequestID: client.RequestID,
		Type:      PacketTypeLogin,
		Body:      password,
	}); err != nil {
		return err
	}
	packet, err := client.RecvPacket()
	if err != nil {
		return err
	}
	switch packet.Type {
	case PacketTypeCommand:
		if packet.RequestID != client.RequestID {
			if err = client.Close(); err != nil {
				return err
			}
			return ErrInvalidPassword
		}
	}
	return nil
}

func (client *RCONClient) SendCommand(command string) (string, error) {
	if err := client.SendPacket(Packet{
		RequestID: client.RequestID,
		Type:      PacketTypeCommand,
		Body:      command,
	}); err != nil {
		return "", err
	}
	res := ""
	for {
		packet, err := client.RecvPacket()
		if err != nil {
			return res, err
		}
		if packet.Type != PacketTypeResponse {
			continue
		}
		res += string(packet.Body)
		if len(packet.Body) < PayloadChunkLength {
			break
		}
	}
	return res, nil
}

func (client *RCONClient) Close() error {
	return client.Connection.Close()
}
