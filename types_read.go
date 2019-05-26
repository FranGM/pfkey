package pfkey

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/FranGM/simplelog"
	"golang.org/x/sys/unix"
)

func (s *SADBMsg) readFromBuffer(buf *bytes.Buffer) error {
	err := binary.Read(buf, binary.LittleEndian, s)
	return err
}

func readSADBAlg(buf *bytes.Buffer) (SADBAlg, error) {
	var newSADBAlg SADBAlg
	err := newSADBAlg.readFromBuffer(buf)
	return newSADBAlg, err
}

func readSADBSupported(buf *bytes.Buffer) (SADBSupported, error) {
	var newSADBSupported SADBSupported
	err := newSADBSupported.readFromBuffer(buf)
	return newSADBSupported, err
}

func readSADBMsg(buf *bytes.Buffer) (SADBMsg, error) {
	var newMsg SADBMsg
	err := newMsg.readFromBuffer(buf)
	return newMsg, err
}

// readNodeFromBuffer reads a SADBAddress and a sockaddr_in struct and returns a Node
func readNodeFromBuffer(buf *bytes.Buffer) (Node, error) {
	var node Node
	var address SADBAddress
	var sckaddr sockAddrIn

	err := address.readFromBuffer(buf)
	if err != nil {
		return node, err
	}

	// TODO: We need to look at the family here and figure out what kind of socket data structure we need to use.
	// For now we'll make do with sockaddr_in
	err = sckaddr.readFromBuffer(buf)
	if err != nil {
		return node, err
	}

	return sckaddr.BuildNode(), nil
}

func readSADBExt(buf *bytes.Buffer) (SADBExt, error) {
	newSADBExt := new(SADBExt)

	// We need to read sadb_ext without advancing the buffer
	// TODO: Need to actually check we have enough bytes in the buffer
	// TODO sadb_ext size shouldn't be hardcoded like this
	const ExtSize = 4
	err := binary.Read(bytes.NewReader(buf.Bytes()[:ExtSize]), binary.LittleEndian, newSADBExt)
	return *newSADBExt, err
}

func readSADBProp(buf *bytes.Buffer) (SADBProp, error) {
	var newSADBProp SADBProp
	err := newSADBProp.readFromBuffer(buf)
	return newSADBProp, err
}

func readSADBComb(buf *bytes.Buffer) (SADBComb, error) {
	var newSADBComb SADBComb
	err := newSADBComb.readFromBuffer(buf)

	return newSADBComb, err
}

func readProposals(buf *bytes.Buffer, propLen uint16) ([]SADBComb, error) {
	combs := make([]SADBComb, 0)
	for i := 1; i < int(propLen); i++ {
		comb, err := readSADBComb(buf)

		if err != nil {
			return combs, err
		}

		simplelog.Debug.Printf("Comb received: %+v", comb)
		combs = append(combs, comb)
	}

	return combs, nil
}

func readAlgorithms(buf *bytes.Buffer) ([]SADBAlg, error) {
	algs := make([]SADBAlg, 0)

	supported, err := readSADBSupported(buf)
	if err != nil {
		return algs, err
	}

	for i := 1; i < int(supported.Len); i++ {
		alg, err := readSADBAlg(buf)
		if err != nil {
			return algs, err
		}
		algs = append(algs, alg)
	}

	return algs, nil
}

func (s *SADBAlg) readFromBuffer(buf *bytes.Buffer) error {
	err := binary.Read(buf, binary.LittleEndian, s)
	return err
}

func (s *SADBXPolicy) readFromBuffer(buf *bytes.Buffer) error {
	err := binary.Read(buf, binary.LittleEndian, s)
	return err
}

func (s *SADBSupported) readFromBuffer(buf *bytes.Buffer) error {
	err := binary.Read(buf, binary.LittleEndian, s)
	return err
}

func (s *SADBLifetime) readFromBuffer(buf *bytes.Buffer) error {
	err := binary.Read(buf, binary.LittleEndian, s)
	return err
}

func (s *SADBAddress) readFromBuffer(buf *bytes.Buffer) error {
	err := binary.Read(buf, binary.LittleEndian, s)
	return err
}

func (s *SADBProp) readFromBuffer(buf *bytes.Buffer) error {
	err := binary.Read(buf, binary.LittleEndian, s)
	return err
}

func (s *SADBComb) readFromBuffer(buf *bytes.Buffer) error {
	err := binary.Read(buf, binary.LittleEndian, s)
	return err
}

func (s *sockAddrIn) readFromBuffer(buf *bytes.Buffer) error {
	err := binary.Read(buf, binary.LittleEndian, s)
	return err
}

func (s *Node) readFromBuffer(buf *bytes.Buffer) error {
	sockAddr := new(sockAddrIn)
	err := binary.Read(buf, binary.LittleEndian, sockAddr)
	if err != nil {
		return err
	}

	simplelog.Debug.Printf("%+v", sockAddr)
	// TODO: Also support IPv6
	if sockAddr.SinFamily != unix.AF_INET {
		return errors.New("Unsupported family in sockaddr")
	}

	node := sockAddr.BuildNode()
	s.Port = node.Port
	s.Addr = node.Addr

	return nil
}

func (s *SADBKey) readFromBuffer(buf *bytes.Buffer) error {
	err := binary.Read(buf, binary.LittleEndian, s)
	return err
}

func (s *SADBSA) readFromBuffer(buf *bytes.Buffer) error {
	err := binary.Read(buf, binary.LittleEndian, s)
	return err
}
