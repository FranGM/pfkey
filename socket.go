package pfkey

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/FranGM/simplelog"

	"golang.org/x/sys/unix"
)

// NewPFKEY opens and returns a new PF_KEY socket
func NewPFKEY() (PFKEY, error) {
	p := PFKEY{}
	fd, err := unix.Socket(unix.AF_KEY, unix.SOCK_RAW, PF_KEY_V2)
	p.socket = &pfkeysocket{fd}
	return p, err
}

// getBytes returns an arbitrary object as a slice of bytes
func getBytes(object interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, object)
	return buf.Bytes(), err
}

// Close closes the existing PF_KEY socket
func (p *PFKEY) Close() error {
	return p.socket.Close()
}

// Close closes the underlying UNIX socket
func (s *pfkeysocket) Close() error {
	return unix.Close(s.fd)
}

// SendMsg sends a message (including all its headers) through a given PF_KEY socket
// It will set the Len field of the message to its appropriate value (given the included headers) before sending it.
func (p *PFKEY) SendMsg(msg Msg) error {
	msg.setMsgLen()

	simplelog.Debug.Printf("This is the full message we're sending: %+v", msg)

	msgBuf := new(msgBuffer)
	err := msg.writeToBuffer(msgBuf)
	if err != nil {
		return err
	}

	err = p.sendBuffer(msgBuf)

	return err
}

// BuildSADBFLUSH builds a SADB_FLUSH message ready to be sent to the kernel.
func BuildSADBFLUSH() Msg {
	msg := Msg{
		Msg: SADBMsg{
			Version: PF_KEY_V2,
			Type:    SADB_FLUSH,
			SAType:  SADB_SATYPE_ESP,
			PID:     uint32(os.Getpid()),
		},
	}
	return msg
}

// SendSADBFLUSH builds and sends a SADB_FLUSH message through this PF_KEY socket.
func (p *PFKEY) SendSADBFLUSH() error {
	msg := BuildSADBFLUSH()

	err := p.SendMsg(msg)
	return err
}

// BuildSADBDUMPMsg builds a SADB_DUMP message ready to be sent to the kernel.
func BuildSADBDUMPMsg() Msg {

	msg := Msg{
		Msg: SADBMsg{
			Version: PF_KEY_V2,
			Errno:   0,
			Type:    SADB_DUMP,
			SAType:  SADB_SATYPE_ESP,
			PID:     uint32(os.Getpid()),
		},
	}
	return msg
}

// SendSADBDumpMsg sends a SADB_DUMP message through this PF_KEY socket.
func (p *PFKEY) SendSADBDumpMsg() error {
	msg := BuildSADBDUMPMsg()

	err := p.SendMsg(msg)
	return err
}

func (s *pfkeysocket) Read(b []byte) (int, error) {
	n, _, err := unix.Recvfrom(s.fd, b, 0)
	return n, err
}

// ReadMsg listens for and parses a message in the PF_KEY socket and stores it into an PFKEYMsg data structure.
func (p *PFKEY) ReadMsg() (Msg, error) {
	newMsg := Msg{}
	readBuf := make([]byte, 8192)

	n, err := p.socket.Read(readBuf)
	if err != nil {
		return newMsg, err
	}

	simplelog.Debug.Printf("Just read %d bytes from socket: %+v", n, readBuf[:n])

	// TODO: Check the value of n here and abort if it doesn't match the expected size

	buf := bytes.NewBuffer(readBuf[:n])

	err = newMsg.Msg.readFromBuffer(buf)
	if err != nil {
		return newMsg, err
	}

	// TODO: We need to do some validation on the message itself. For example:
	// TODO: Validate that the version is valid (only one possible value: PF_KEY_V2)
	// TODO: Validate that the len field makes sense, and use it when parsing the message
	// TODO: Validate that we get as much data as the len field says we're getting

	// Now we read the extensions, as the original message includes the full
	//  size of message + extensions, we should be able to loop until we know
	//  the buffer should be empty.
	// TODO: Given that we know the expected size maybe we should loop until we know we've read the whole message instead of exhausting the buffer?
	for buf.Len() > 0 {

		newExt, err := readSADBExt(buf)
		if err != nil {
			return newMsg, err
		}

		switch newExt.Type {
		case SADB_EXT_SA:
			var newSA SADBSA
			err := newSA.readFromBuffer(buf)
			if err != nil {
				return newMsg, err
			}
			newMsg.SetSA(newSA)
		case SADB_EXT_LIFETIME_HARD:
			var newLT SADBLifetime
			err = newLT.readFromBuffer(buf)
			if err != nil {
				return newMsg, err
			}
			newMsg.SetLifetimeHard(newLT)

		case SADB_EXT_LIFETIME_SOFT:
			var newLT SADBLifetime
			err = newLT.readFromBuffer(buf)
			if err != nil {
				return newMsg, err
			}
			newMsg.SetLifetimeSoft(newLT)

		case SADB_EXT_LIFETIME_CURRENT:
			var newLT SADBLifetime
			err = newLT.readFromBuffer(buf)
			if err != nil {
				return newMsg, err
			}
			newMsg.SetLifetimeCurrent(newLT)

		case SADB_EXT_ADDRESS_SRC:
			newNode, err := readNodeFromBuffer(buf)
			if err != nil {
				return newMsg, err
			}
			newMsg.SetAddressSrc(newNode)
		case SADB_EXT_ADDRESS_DST:
			newNode, err := readNodeFromBuffer(buf)
			if err != nil {
				return newMsg, err
			}
			newMsg.SetAddressDst(newNode)
		case SADB_EXT_SUPPORTED_AUTH:
			newMsg.Extensions.AuthAlgorithms, err = readAlgorithms(buf)
			if err != nil {
				return newMsg, err
			}
			newMsg.Present.AuthAlgorithms = true
		case SADB_EXT_SUPPORTED_ENCRYPT:
			newMsg.Extensions.EncryptAlgorithms, err = readAlgorithms(buf)
			if err != nil {
				return newMsg, err
			}
			newMsg.Present.EncryptAlgorithms = true
		case SADB_EXT_PROPOSAL:
			err = newMsg.Extensions.Proposal.readFromBuffer(buf)
			simplelog.Info.Printf("-----> Proposal length is %d", newMsg.Extensions.Proposal.Len)
			if err != nil {
				return newMsg, err
			}

			newMsg.Extensions.ProposalCombs, err = readProposals(buf, newMsg.Extensions.Proposal.Len)
			if err != nil {
				return newMsg, err
			}
			newMsg.Present.Proposal = true

		case SADB_EXT_ADDRESS_PROXY:
			extensionNotImplemented(buf, newExt)
		case SADB_EXT_KEY_AUTH:
			extensionNotImplemented(buf, newExt)
		case SADB_EXT_KEY_ENCRYPT:
			extensionNotImplemented(buf, newExt)
		case SADB_X_EXT_SA2:
			extensionNotImplemented(buf, newExt)
		case SADB_X_EXT_POLICY:
			err = newMsg.Extensions.XPolicy.readFromBuffer(buf)
			if err != nil {
				simplelog.Fatal.Println(err)
			}
			newMsg.Present.XPolicy = true

		default:
			return newMsg, fmt.Errorf("received unexpected extension when parsing message: %d", newExt.Type)
		}
	}

	if newMsg.Present.Proposal {
		encoded := make([]byte, 500)
		base64.RawStdEncoding.Encode(encoded, readBuf[:n])
		ioutil.WriteFile(fmt.Sprintf("%s", time.Now()), encoded, 0666)
	}

	return newMsg, nil
}

// Write sends the contents of b over this PF_KEY socket. Returns the number of bytes written.
func (s *pfkeysocket) Write(b []byte) (int, error) {
	n, err := unix.Write(s.fd, b)
	return n, err
}

func (p *PFKEY) sendBuffer(buf *msgBuffer) error {
	n, err := p.socket.Write(buf.buf.Bytes())
	// TODO: Might want to check if we didn't write as much as we should have.
	simplelog.Debug.Printf("Just sent %d bytes through the socket", n)
	return err
}
