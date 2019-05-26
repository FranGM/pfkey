package pfkey

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/FranGM/simplelog"

	"golang.org/x/sys/unix"
)

func (s *SADBMsg) fromBytes(bytesBuf []byte) error {
	buf := bytes.NewReader(bytesBuf)
	err := binary.Read(buf, binary.LittleEndian, s)
	return err
}

// BuildSADBGETSPI builds a SADB_GETSPI message
func BuildSADBGETSPI(seq uint32, src Node, dst Node) (Msg, error) {

	msg := Msg{
		Msg: SADBMsg{
			Version: PF_KEY_V2,
			Errno:   0,
			Type:    SADB_GETSPI,
			Seq:     seq,
			SAType:  SADB_SATYPE_ESP,
			PID:     uint32(os.Getpid()),
		},
	}

	simplelog.Debug.Printf("Requesting SADB SPI with this message: %+v", msg)

	msg.SetAddressSrc(src)
	msg.SetAddressDst(dst)

	msg.SetSPIRANGE(spiRangeMin, spiRangeMax)

	return msg, nil
}

// SendSADBGETSPI sends a SADB_GETSPI message to the PF_KEY socket.
func (p *PFKEY) SendSADBGETSPI(seq uint32, src Node, dst Node) error {
	msg, err := BuildSADBGETSPI(seq, src, dst)
	if err != nil {
		return nil
	}

	err = p.SendMsg(msg)
	return err
}

// BuildNode generates a Node object pointing to the same host as this sockAddrIn struct
func (s sockAddrIn) BuildNode() Node {

	if s.SinFamily != unix.AF_INET {
		simplelog.Fatal.Println("Not implemented family in sockaddr")
	}

	n := Node{
		Addr: net.IPv4(s.SinAddr[0], s.SinAddr[1], s.SinAddr[2], s.SinAddr[3]),
		Port: s.SinPort,
	}
	return n
}

// TODO: This should support setting the family as well
func (n Node) buildSockAddr() sockAddrIn {

	sAddr := sockAddrIn{
		SinFamily: unix.AF_INET,
		SinPort:   n.Port,
		SinAddr:   n.AddrAsArray(),
	}
	simplelog.Debug.Printf("Built sockaddr struct: %+v", sAddr)

	return sAddr
}

func (s *SADBKey) setLen(keyBits int) {
	s.Len = uint16((1 + (keyBits / 8) + 7) / 8)
}

func extensionNotImplemented(buf *bytes.Buffer, ext SADBExt) {
	simplelog.Warning.Printf("Extension %d not implemented yet, advancing buffer %d bytes", ext.Type, ext.Len)
	buf.Next(int(ext.Len * 8))
}

// RetrieveSADBDump listens for a reply to a SADB_DUMP message from the kernel and returns all the relevant SADB_DUMP messages.
// It will ignore and skip messages of any other type received through the socket.
func (p *PFKEY) RetrieveSADBDump() ([]Msg, error) {
	messages := make([]Msg, 0)

	for {
		msg, err := p.ReadMsg()
		if err != nil {
			return messages, err
		}

		// TODO: Check the type of message here. We'll probably want to skip any message that's not a SADB_DUMP message
		// TODO: Probably worth also checking the PID of the message to ensure we're looking at a reply to *our* message.

		if msg.Msg.Errno == uint8(unix.ENOENT) {
			break
		}

		if msg.Msg.Errno != 0 {
			simplelog.Debug.Printf("Received %+v", msg.Msg)
			return messages, fmt.Errorf("Got error from pfkey. errno=%d ", msg.Msg.Errno)
		}

		// TODO: Here we should check that we have actually received all the extensions that we expected.

		messages = append(messages, msg)

		// The last message in SADB_DUMP will have its seq number as 0
		if msg.Msg.Seq == 0 {
			break
		}
		simplelog.Debug.Printf("End of loop: %+v", msg)
	}

	return messages, nil
}

// BuildSADBDELETE builds a new SADB_DELETE message for the given spi and nodes.
func BuildSADBDELETE(spi uint32, src Node, dst Node) (*Msg, error) {
	p := &Msg{}

	p.Msg = SADBMsg{
		Type:   SADB_DELETE,
		SAType: SADB_SATYPE_ESP,
		PID:    uint32(os.Getpid()),
	}

	p.SetSA(SADBSA{
		SPI: spi,
	})

	p.SetAddressSrc(src)
	p.SetAddressDst(dst)

	return p, nil
}

// BuildSADBUPDATE builds a SADB_UPDATE message to finish establishing a mature association between src and dst.
func BuildSADBUPDATE(seq uint32, spi uint32, src Node, dst Node, encryptKey []byte) (*Msg, error) {
	// An ADD message is essentially an UPDATE message with a different Type set, so reuse that.
	m, err := BuildSADBADD(seq, spi, src, dst, encryptKey)
	m.Msg.Type = SADB_UPDATE

	return m, err
}

// BuildSADBADD builds a SADB_ADD message to create a mature association between src and dst.
func BuildSADBADD(seq uint32, spi uint32, src Node, dst Node, encryptKey []byte) (*Msg, error) {
	// TODO: We should also do some validation to make sure the message we're building makes sense (valid encryptKey, etc)

	p := &Msg{}

	p.Msg = SADBMsg{
		Type:   SADB_ADD,
		SAType: SADB_SATYPE_ESP,
		Seq:    seq,
		PID:    uint32(os.Getpid()),
	}

	p.SetSA(SADBSA{
		Encrypt: 12,
		SPI:     spi,
		State:   SADB_SASTATE_MATURE,
	})

	// TODO: Make the lifetimes configurable
	p.SetLifetimeSoft(SADBLifetime{
		Addtime: 60,
	})

	p.SetLifetimeHard(SADBLifetime{
		Addtime: 90,
	})

	p.SetAddressSrc(src)

	p.SetAddressDst(dst)

	// TODO: Adapt this to the size of encryptKey and do some sanity check depending what encryption algorithm we're using
	keyBits := 256

	p.SetEncryptKey(encryptKey, keyBits)

	simplelog.Info.Printf("keybits=%d and the actual key is %+v", keyBits, encryptKey)

	p.setMsgLen()

	return p, nil
}

// BuildSADBREGISTERMsg builds a SADB_REGISTER message that can be sent to the kernel.
func BuildSADBREGISTERMsg() Msg {

	msg := Msg{
		Msg: SADBMsg{
			Version: PF_KEY_V2,
			Errno:   0,
			Type:    SADB_REGISTER,
			SAType:  SADB_SATYPE_ESP,
			PID:     uint32(os.Getpid())}}
	return msg
}

// SendSADBRegisterMsg send a SADB_REGISTER message through this PF_KEY socket.
func (p *PFKEY) SendSADBRegisterMsg() error {
	msg := BuildSADBREGISTERMsg()

	err := p.SendMsg(msg)
	if err != nil {
		return err
	}

	return nil
}
