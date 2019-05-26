package pfkey

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

var expectedAddMsg, expectedUpdateMsg Msg

func init() {
	expectedAddMsg = Msg{
		Msg: SADBMsg{
			Version: PF_KEY_V2,
			Type:    SADB_ADD,
			SAType:  SADB_SATYPE_ESP,
			Len:     23,
			Seq:     1337,
			PID:     uint32(os.Getpid()),
		},
		Present: sadbExtensionsChecklist{
			SA:           true,
			AddressSrc:   true,
			AddressDst:   true,
			EncryptKey:   true,
			LifetimeSoft: true,
			LifetimeHard: true,
		},
		Extensions: sadbExtensions{
			LifetimeHard: SADBLifetime{
				Len:     4,
				ExtType: 3,
				Addtime: 90,
			},
			LifetimeSoft: SADBLifetime{

				Len:     4,
				ExtType: 4,
				Addtime: 60,
			},
			SA: SADBSA{
				Len:     2,
				ExtType: 1,
				SPI:     31337,
				State:   SADB_SASTATE_MATURE,
				Encrypt: 12,
			},
			AddressSrc: SADBAddress{
				Len:       3,
				ExtType:   5,
				PrefixLen: 32,
			},
			SockAddrSrc: sockAddrIn{
				SinFamily: unix.AF_INET,
				SinAddr:   [4]byte{1, 2, 3, 4},
			},
			AddressDst: SADBAddress{
				Len:       3,
				ExtType:   6,
				PrefixLen: 32,
			},
			SockAddrDst: sockAddrIn{
				SinFamily: unix.AF_INET,
				SinAddr:   [4]byte{5, 6, 7, 8},
			},
			EncryptKey: SADBKey{
				Len:     5,
				ExtType: 9,
				Bits:    256,
			},
			EncryptKeyBits: []byte{40, 141, 178, 141, 242, 74, 142, 67, 237, 231, 145, 81, 148, 10, 249, 253, 77, 164, 119, 141, 106, 73, 193, 49, 35, 84, 139, 157, 95, 216, 244, 48},
		},
	}

	expectedUpdateMsg = expectedAddMsg
	expectedUpdateMsg.Msg.Type = SADB_UPDATE
}

func TestNode(t *testing.T) {
	// TODO: Test at least AsArray() method from Node type
}

func TestGetSPI(t *testing.T) {

	seq := uint32(1234)
	src := Node{Addr: net.IPv4(1, 2, 3, 4)}
	dst := Node{Addr: net.IPv4(5, 6, 7, 8)}

	expectedSPIMsg := Msg{
		Msg: SADBMsg{
			Version: PF_KEY_V2,
			Errno:   0,
			Type:    SADB_GETSPI,
			Seq:     seq,
			SAType:  SADB_SATYPE_ESP,
			PID:     uint32(os.Getpid()),
		},
		Present: sadbExtensionsChecklist{
			AddressDst: true,
			AddressSrc: true,
			SPIRange:   true,
		},
		Extensions: sadbExtensions{
			SPIRange: SADBSPIRange{
				Min:     10,
				Max:     10000000,
				ExtType: 16,
				Len:     2,
			},
			AddressSrc: SADBAddress{
				Len:       3,
				ExtType:   5,
				PrefixLen: 32,
			},
			SockAddrSrc: sockAddrIn{
				SinFamily: unix.AF_INET,
				SinAddr:   [4]byte{1, 2, 3, 4},
			},
			AddressDst: SADBAddress{
				Len:       3,
				ExtType:   6,
				PrefixLen: 32,
			},
			SockAddrDst: sockAddrIn{
				SinFamily: unix.AF_INET,
				SinAddr:   [4]byte{5, 6, 7, 8},
			},
		},
	}

	msg, err := BuildSADBGETSPI(seq, src, dst)
	if err != nil {
		t.Error(err)
	}

	if err = compareMessages(expectedSPIMsg, msg); err != nil {
		t.Error(err)
	}
}

func TestBuildSADBADD(t *testing.T) {
	seq := uint32(1337)
	spi := uint32(31337)
	src := Node{Addr: net.IPv4(1, 2, 3, 4)}
	dst := Node{Addr: net.IPv4(5, 6, 7, 8)}
	encryptKeyBits := []byte{40, 141, 178, 141, 242, 74, 142, 67, 237, 231, 145, 81, 148, 10, 249, 253, 77, 164, 119, 141, 106, 73, 193, 49, 35, 84, 139, 157, 95, 216, 244, 48}

	msg, err := BuildSADBADD(seq, spi, src, dst, encryptKeyBits)
	if err != nil {
		t.Error(err)
	}

	msg.setMsgLen()

	if err = compareMessages(expectedAddMsg, *msg); err != nil {
		t.Error(err)
	}
}

func TestBuildSADBUPDATE(t *testing.T) {
	seq := uint32(1337)
	spi := uint32(31337)
	src := Node{Addr: net.IPv4(1, 2, 3, 4)}
	dst := Node{Addr: net.IPv4(5, 6, 7, 8)}
	encryptKeyBits := []byte{40, 141, 178, 141, 242, 74, 142, 67, 237, 231, 145, 81, 148, 10, 249, 253, 77, 164, 119, 141, 106, 73, 193, 49, 35, 84, 139, 157, 95, 216, 244, 48}

	msg, err := BuildSADBUPDATE(seq, spi, src, dst, encryptKeyBits)
	if err != nil {
		t.Error(err)
	}

	if err = compareMessages(expectedUpdateMsg, *msg); err != nil {
		t.Error(err)
	}
}

func TestSPI(t *testing.T) {
	s := SADBSA{
		SPI: 421321321,
	}

	spi := s.GetSPI()

	// GetSPI reverses the "endianness" of what the struct stores
	var expected uint32 = 1775901721

	if spi != expected {
		t.Errorf("GetSPI failed. Got %d, expected %d", spi, expected)

	}
}
