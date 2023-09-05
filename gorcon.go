package gorcon

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
)

type PacketType int32

const (
	PacketLogin    PacketType = 3
	PacketCommand  PacketType = 2
	PacketResponse PacketType = 0

	RequestIDStart    int32 = 6516583
	PacketChunkLength int   = 4096
)

var (
	MCEndian        binary.ByteOrder = binary.LittleEndian
	InvalidPassword error            = errors.New("invalid RCON password")
	counter         int32            = 0
)

type RCONClient struct {
	Address    string
	RequestID  int32
	Connection net.Conn
}

type Packet struct {
	RequestID int32
	Type      PacketType
	Data      string
}

func NewRCONClient(host string, port uint16) *RCONClient {
	counter++
	return &RCONClient{
		Address:   host + ":" + strconv.FormatUint(uint64(port), 10),
		RequestID: RequestIDStart + counter - 1,
	}
}

func (client *RCONClient) SendPacket(packet Packet) error {
	payload := []byte(packet.Data)
	payloadLength := len(payload)
	data := make([]byte, 15+payloadLength)
	MCEndian.PutUint32(data, uint32(10+payloadLength))
	MCEndian.PutUint32(data[4:], uint32(packet.RequestID))
	MCEndian.PutUint32(data[8:], uint32(packet.Type))
	copy(data[12:], payload)
	data[13+payloadLength] = 0
	data[14+payloadLength] = 0
	_, err := client.Connection.Write(data)
	return err
}

func (client *RCONClient) RecvPacket() (*Packet, error) {
	rawPacketLength := make([]byte, 4)
	_, err := client.Connection.Read(rawPacketLength)
	if err != nil {
		return nil, err
	}
	packetLength := MCEndian.Uint32(rawPacketLength)
	rawPacket := make([]byte, packetLength)
	_, err = client.Connection.Read(rawPacket)
	if err != nil {
		return nil, err
	}
	packet := &Packet{}
	packet.RequestID = int32(MCEndian.Uint32(rawPacket))
	packet.Type = PacketType(MCEndian.Uint32(rawPacket[4:]))
	packet.Data = string(rawPacket[8:(packetLength - 9)])
	return packet, nil
}

func (client *RCONClient) Login(password string) error {
	connection, err := net.Dial("tcp", client.Address)
	if err != nil {
		return err
	}
	client.Connection = connection
	err = client.SendPacket(Packet{
		RequestID: client.RequestID,
		Type:      PacketLogin,
		Data:      password,
	})
	if err != nil {
		return err
	}
	packet, err := client.RecvPacket()
	if err != nil {
		return err
	}
	switch packet.Type {
	case PacketCommand:
		if packet.RequestID != client.RequestID {
			return InvalidPassword
		}
	}
	return nil
}

func (client *RCONClient) SendCommand(command string) (string, error) {
	err := client.SendPacket(Packet{
		RequestID: client.RequestID,
		Type:      PacketCommand,
		Data:      command,
	})
	if err != nil {
		return "", err
	}
	res := ""
	for {
		packet, err := client.RecvPacket()
		if err != nil {
			return res, err
		}
		if len(packet.Data) < PacketChunkLength {
			break
		}
		res += packet.Data
	}
	return res, nil
}

func (client *RCONClient) Close() error {
	return client.Connection.Close()
}
