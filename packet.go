package gorcon

import (
	"io"

	"golang.org/x/exp/slices"
)

type PacketType int32

const (
	PacketTypeCommand  PacketType = 2
	PacketTypeLogin    PacketType = 3
	PacketTypeResponse PacketType = 0
	PayloadChunkLength int        = 4096
)

type BinaryPacket struct {
	RequestID int32
	Type      PacketType
	Body      []byte
}

type Packet struct {
	RequestID int32
	Type      PacketType
	Body      string
}

func (bp *BinaryPacket) Text() (*Packet, error) {
	zero := slices.Index(bp.Body, 0)
	if zero == -1 {
		return nil, &RCONErrorNotZeroTerminatedPayload{
			RequestID: bp.RequestID,
			Type:      bp.Type,
			Payload:   bp.Body,
		}
	}
	return &Packet{
		RequestID: bp.RequestID,
		Type:      bp.Type,
		Body:      string(bp.Body[:zero]),
	}, nil
}

func ReadBinaryPacket(r io.Reader) (*BinaryPacket, error) {
	rawLength := make([]byte, 4)
	n, err := r.Read(rawLength)
	if err != nil {
		return nil, err
	}
	if n != 4 {
		return nil, &RCONErrorInvalidLength{
			Expected:  4,
			Got:       n,
			Condition: Exactly,
		}
	}
	length := MCEndian.Uint32(rawLength)
	if length < 10 || length > 1456 {
		return nil, &RCONErrorInvalidLength{
			Expected:  10,
			Expected2: 1456,
			Got:       n,
			Condition: Range,
		}
	}
	data := make([]byte, length)
	n, err = r.Read(data)
	if err != nil {
		return nil, err
	}
	if n != int(length) {
		return nil, &RCONErrorInvalidLength{
			Expected:  int(length),
			Got:       n,
			Condition: Exactly,
		}
	}
	return &BinaryPacket{
		RequestID: int32(MCEndian.Uint32(data)),
		Type:      PacketType(MCEndian.Uint32(data[4:])),
		Body:      data[8 : len(data)-1],
	}, nil
}

func ReadPacket(r io.Reader) (*Packet, error) {
	bp, err := ReadBinaryPacket(r)
	if err != nil {
		return nil, err
	}
	zero := slices.Index(bp.Body, 0)
	if zero == -1 {
		return nil, &RCONErrorNotZeroTerminatedPayload{
			RequestID: bp.RequestID,
			Type:      bp.Type,
			Payload:   bp.Body,
		}
	}
	return &Packet{
		RequestID: bp.RequestID,
		Type:      bp.Type,
		Body:      string(bp.Body[:zero]),
	}, nil
	/*rawLength := make([]byte, 4)
	n, err := r.Read(rawLength)
	if err != nil {
		return nil, err
	}
	if n != 4 {
		return nil, &RCONErrorInvalidLength{
			Expected:  4,
			Got:       n,
			Condition: Exactly,
		}
	}
	length := MCEndian.Uint32(rawLength)
	if length < 10 || length > 1456 {
		return nil, &RCONErrorInvalidLength{
			Expected:  10,
			Expected2: 1456,
			Got:       n,
			Condition: Range,
		}
	}
	payload := make([]byte, length)
	n, err = r.Read(payload)
	if err != nil {
		return nil, err
	}
	if n != int(length) {
		return nil, &RCONErrorInvalidLength{
			Expected:  int(length),
			Got:       n,
			Condition: Exactly,
		}
	}
	data := payload[8 : length-2]
	zero := slices.Index(data, 0)
	if zero == -1 {
		return nil, &RCONErrorNotZeroTerminatedPayload{
			RequestID: int32(MCEndian.Uint32(payload)),
			Type:      PacketType(MCEndian.Uint32(payload[4:])),
			Payload:   data,
		}
	}
	return &Packet{
		RequestID: int32(MCEndian.Uint32(payload)),
		Type:      PacketType(MCEndian.Uint32(payload[4:])),
		Body:      string(data[:zero]),
	}, nil*/
}

func WriteBinaryPacket(w io.Writer, packet BinaryPacket) (int, error) {
	payload := []byte(packet.Body)
	payloadLength := len(payload)
	data := make([]byte, 15+payloadLength)
	MCEndian.PutUint32(data, uint32(11+payloadLength))
	MCEndian.PutUint32(data[4:], uint32(packet.RequestID))
	MCEndian.PutUint32(data[8:], uint32(packet.Type))
	copy(data[12:], payload)
	data[13+payloadLength] = 0
	data[14+payloadLength] = 0
	return w.Write(data)
}

func WritePacket(w io.Writer, packet Packet) (int, error) {
	payload := []byte(packet.Body)
	payloadLength := len(payload)
	data := make([]byte, 14+payloadLength)
	MCEndian.PutUint32(data, uint32(10+payloadLength))
	MCEndian.PutUint32(data[4:], uint32(packet.RequestID))
	MCEndian.PutUint32(data[8:], uint32(packet.Type))
	copy(data[12:], payload)
	data[13+payloadLength] = 0
	return w.Write(data)
}
