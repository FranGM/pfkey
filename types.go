package pfkey

import (
	"bytes"
	"io"
	"net"
)

// msgBuffer is a buffer that allows us to write arbitrary data structures into a bytes.Buffer
type msgBuffer struct {
	buf bytes.Buffer
}

// PFKEY represents the connection to a PF_KEY socket.
type PFKEY struct {
	socket io.ReadWriteCloser
}

type pfkeysocket struct {
	fd int
}

// sadbExtensions can hold all the possible extensions to a sadb_msg.
type sadbExtensions struct {
	SA                SADBSA
	LifetimeCurrent   SADBLifetime
	LifetimeSoft      SADBLifetime
	LifetimeHard      SADBLifetime
	AddressSrc        SADBAddress
	SockAddrSrc       sockAddrIn
	AddressDst        SADBAddress
	SockAddrDst       sockAddrIn
	Proposal          SADBProp
	ProposalCombs     []SADBComb
	AuthKey           SADBKey
	AuthKeyBits       []byte
	AuthAlgorithms    []SADBAlg
	EncryptKey        SADBKey
	EncryptKeyBits    []byte
	EncryptAlgorithms []SADBAlg
	SPIRange          SADBSPIRange
	XPolicy           SADBXPolicy
}

// sadbExtensionsChecklist holds a checklist to mark if a given SADBMsg includes certain extensions or not.
type sadbExtensionsChecklist struct {
	SA                bool
	LifetimeCurrent   bool
	LifetimeSoft      bool
	LifetimeHard      bool
	AddressSrc        bool
	AddressDst        bool
	Proposal          bool
	AuthKey           bool
	EncryptKey        bool
	AuthAlgorithms    bool
	EncryptAlgorithms bool
	SPIRange          bool
	XPolicy           bool
}

// Msg holds a full message that can be sent/received through a PF_KEY socket.
// It includes all extensions and additional data that can be sent/received such as key data.
type Msg struct {
	Msg        SADBMsg
	Extensions sadbExtensions
	Present    sadbExtensionsChecklist
}

// Registration holds the data received from the kernel when we register throught the PF_KEY socket.
type Registration struct {
	AuthAlgorithms []SADBAlg
	EncrAlgorithms []SADBAlg
}

// Node represents one of the two ends of an SA.
type Node struct {
	Addr net.IP
	Port uint16
}

// AddrAsArray returns the Address of this node as a 4-byte array
// TODO: This obviously only works for IPv4
func (n *Node) AddrAsArray() [4]byte {
	return [4]byte{n.Addr[12], n.Addr[13], n.Addr[14], n.Addr[15]}
}

type sockAddrIn struct {
	SinFamily int16
	SinPort   uint16
	SinAddr   [4]byte
	SinZero   [8]byte //padding
}
