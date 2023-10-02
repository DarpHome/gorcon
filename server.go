package gorcon

import (
	"fmt"
	"net"
	"reflect"
)

type RCONContext struct {
	Closed     bool
	Connection net.Conn
	RequestID  int32
	Server     *RCONServer
}

type RCONCommandContext struct {
	Command   string
	Context   *RCONContext
	RequestID int32
}

type RCONPasswordChecker func(string) bool
type RCONCommandHandler interface{}
type RCONErrorHandler func(*RCONCommandContext, *RCONContext, error)
type RCONDispatcher func(*RCONContext, *BinaryPacket) error

type RCONServer struct {
	Config         RCONServerConfig
	Checker        RCONPasswordChecker
	CommandHandler RCONCommandHandler
	ErrorHandler   RCONErrorHandler
	Listener       net.Listener
	Dispatchers    map[PacketType]RCONDispatcher
}

type RCONErrorCondition int

const (
	AtLeast RCONErrorCondition = iota
	Exactly
	Range
	TooLarge
)

type RCONErrorInvalidLength struct {
	Expected  int
	Expected2 int
	Got       int
	Condition RCONErrorCondition
}

type RCONErrorNotZeroTerminatedPayload struct {
	RequestID int32
	Type      PacketType
	Payload   []byte
}

func (e *RCONErrorNotZeroTerminatedPayload) Error() string {
	return "payload is not zero-terminated"
}

func (e *RCONErrorInvalidLength) Error() string {
	switch e.Condition {
	case AtLeast:
		return fmt.Sprintf("expected at least %d bytes, got %d", e.Expected, e.Got)
	case Exactly:
		return fmt.Sprintf("expected %d bytes, got %d", e.Expected, e.Got)
	case Range:
		return fmt.Sprintf("expected number between %d and %d range, got %d", e.Expected, e.Expected2, e.Got)
	case TooLarge:
		return fmt.Sprintf("expected less than %d bytes, got %d", e.Expected, e.Got)
	}
	return ""
}

var (
	DefaultChecker RCONPasswordChecker = func(string) bool {
		return false
	}
	DefaultCommandHandler RCONCommandHandler = func(*RCONCommandContext) []string {
		return []string{}
	}
	DefaultErrorHandler RCONErrorHandler = func(_ *RCONCommandContext, _ *RCONContext, _ error) {

	}
)

func NewRCONServer(config *RCONServerConfig) *RCONServer {
	if config == nil {
		config = &RCONServerConfig{}
	}
	return &RCONServer{
		Config:         *config,
		Checker:        DefaultChecker,
		CommandHandler: DefaultCommandHandler,
		ErrorHandler:   DefaultErrorHandler,
		Listener:       nil,
		Dispatchers:    map[PacketType]RCONDispatcher{},
	}
}

func (rs *RCONServer) Check(checker RCONPasswordChecker) *RCONServer {
	rs.Checker = checker
	return rs
}

func (rs *RCONServer) OnCommand(commandHandler RCONCommandHandler) *RCONServer {
	if commandHandler == nil {
		rs.CommandHandler = nil
		return rs
	}
	switch commandHandler.(type) {
	case func(*RCONCommandContext):
		rs.CommandHandler = commandHandler
	case func(*RCONCommandContext) []string:
		rs.CommandHandler = commandHandler
	}
	return rs
}

func (rs *RCONServer) OnError(errorHandler RCONErrorHandler) *RCONServer {
	rs.ErrorHandler = errorHandler
	return rs
}

func ForPassword(password string) RCONPasswordChecker {
	return func(providedPassword string) bool {
		return providedPassword == password
	}
}

func Collect(s string) []string {
	chunks := []string{}
	for i := 0; i < len(s); i += PayloadChunkLength {
		chunks = append(chunks, s[i:min(len(s), i+PayloadChunkLength)])
	}
	return chunks
}

func NewContext(conn net.Conn, server *RCONServer) *RCONContext {
	return &RCONContext{
		Connection: conn,
		Server:     server,
	}
}

func (ctx *RCONContext) Close() *RCONContext {
	ctx.Closed = true
	if !ctx.Closed {
		ctx.Connection.Close()
	}
	return ctx
}

func (ctx *RCONContext) RecvPacket() (*Packet, error) {
	return ReadPacket(ctx.Connection)
}

func (ctx *RCONContext) SendPacket(packet Packet) error {
	_, err := WritePacket(ctx.Connection, packet)
	return err
}

func (ctx *RCONContext) RecvBinaryPacket() (*BinaryPacket, error) {
	return ReadBinaryPacket(ctx.Connection)
}

func (ctx *RCONContext) SendBinaryPacket(packet BinaryPacket) error {
	_, err := WriteBinaryPacket(ctx.Connection, packet)
	return err
}

func (ctx *RCONContext) RawSend(requestID int32, payload string) error {
	return ctx.SendPacket(Packet{
		RequestID: requestID,
		Type:      PacketTypeResponse,
		Body:      payload,
	})
}

func (ctx *RCONContext) Send(requestID int32, payload string) error {
	chunks := Collect(payload)
	if len(chunks) == 0 {
		chunks = []string{""}
	}
	if len(chunks[len(chunks)-1]) == 4096 {
		chunks = append(chunks, "")
	}
	for _, chunk := range chunks {
		if err := ctx.RawSend(requestID, chunk); err != nil {
			return err
		}
	}
	return nil
}

func NewCommandContext(context *RCONContext, packet *Packet) *RCONCommandContext {
	return &RCONCommandContext{
		Command:   packet.Body,
		Context:   context,
		RequestID: packet.RequestID,
	}
}

func (cctx *RCONCommandContext) Reply(payload string) error {
	return cctx.Context.Send(cctx.RequestID, payload)
}

func (rs *RCONServer) handleConnection(conn net.Conn) {
	ctx := NewContext(conn, rs)
	defer func() {
		if err := ctx.Connection.Close(); err != nil {
			if rs.ErrorHandler != nil {
				rs.ErrorHandler(nil, ctx, err)
			}
		}
	}()
	packet, err := ctx.RecvPacket()
	if err != nil {
		if rs.ErrorHandler != nil {
			rs.ErrorHandler(nil, ctx, err)
		}
		return
	}
	ctx.RequestID = packet.RequestID
	if packet.Type != PacketTypeLogin {
		return
	}
	if !ctx.Server.Checker(packet.Body) {
		err = ctx.SendPacket(Packet{
			RequestID: -1,
			Type:      PacketTypeCommand,
		})
		if err != nil && rs.ErrorHandler != nil {
			rs.ErrorHandler(nil, ctx, err)
		}
		if err = ctx.Connection.Close(); err != nil {
			rs.ErrorHandler(nil, ctx, err)
		}
		return
	}
	if err = ctx.SendPacket(Packet{
		RequestID: ctx.RequestID,
		Type:      PacketTypeResponse,
		Body:      "",
	}); err != nil {
		if rs.ErrorHandler != nil {
			rs.ErrorHandler(nil, ctx, err)
		}
		return
	}
	for !ctx.Closed {
		packet, err := ctx.RecvBinaryPacket()
		if err != nil {
			if rs.ErrorHandler != nil {
				rs.ErrorHandler(nil, ctx, err)
			}
			break
		}
		dp, ok := rs.Dispatchers[packet.Type]
		if ok {
			if err := dp(ctx, packet); err != nil && rs.ErrorHandler != nil {
				rs.ErrorHandler(nil, ctx, err)
			}
			continue
		}
		switch packet.Type {
		case PacketTypeLogin:
		case PacketTypeResponse:
			continue
		case PacketTypeCommand:
			tp, err := packet.Text()
			if err != nil {
				if rs.ErrorHandler != nil {
					rs.ErrorHandler(nil, ctx, err)
				}
				continue
			}
			cctx := NewCommandContext(ctx, tp)
			if rs.CommandHandler != nil {
				switch rs.CommandHandler.(type) {
				case func(*RCONCommandContext):
					f := rs.CommandHandler.(func(*RCONCommandContext))
					if (rs.Config.Flags & CommandInGoroutine) != 0 {
						go f(cctx)
					} else {
						f(cctx)
					}
				case func(*RCONCommandContext) []string:
					chunks := rs.CommandHandler.(func(*RCONCommandContext) []string)(cctx)
					if len(chunks) == 0 {
						chunks = []string{""}
					}
					if len(chunks[len(chunks)-1]) == 4096 {
						chunks = append(chunks, "")
					}
				sendingChunks:
					for _, chunk := range chunks {
						if err := ctx.SendPacket(Packet{
							RequestID: cctx.RequestID,
							Type:      PacketTypeResponse,
							Body:      chunk,
						}); err != nil {
							rs.ErrorHandler(cctx, ctx, err)
							break sendingChunks
						}
					}
				default:
					if rs.ErrorHandler != nil {
						rs.ErrorHandler(cctx, nil, fmt.Errorf("unknown handler type: %v", reflect.TypeOf(rs.CommandHandler)))
					}
				}
			}
		default:
			ctx.SendPacket(Packet{
				RequestID: packet.RequestID,
				Type:      PacketTypeResponse,
				Body:      fmt.Sprintf("Unknown request %2x", packet.Type),
			})
		}
	}
	if err = conn.Close(); err != nil && rs.ErrorHandler != nil {
		rs.ErrorHandler(nil, nil, err)
	}
}

func (rs *RCONServer) Run(address string) error {
	if rs.Listener != nil {
		if err := rs.Close(); err != nil {
			return err
		}
	}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	rs.Listener = ln
	for rs.Listener != nil {
		conn, err := rs.Listener.Accept()
		if err != nil {
			rs.ErrorHandler(nil, nil, err)
			continue
		}
		go rs.handleConnection(conn)
	}
	return nil
}

func (rs *RCONServer) Close() error {
	if rs.Listener == nil {
		return nil
	}
	if err := rs.Listener.Close(); err != nil {
		return err
	}
	rs.Listener = nil
	return nil
}

func (rs *RCONServer) On(pt PacketType, dispatcher RCONDispatcher) *RCONServer {
	rs.Dispatchers[pt] = dispatcher
	return rs
}
