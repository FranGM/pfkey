package pfkey

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TODO: This file is by no means great, let's try to reduce at least some of the code duplication
//    so we can add more tests with more thorough checking.

// insertPidInMsg inserts the PID of the current process into
// the right position of the given message
func insertPidInMsg(msg []byte) []byte {

	pidBuf := make([]byte, 4)
	pid := uint32(os.Getpid())
	binary.LittleEndian.PutUint32(pidBuf, pid)

	msg[12] = pidBuf[0]
	msg[13] = pidBuf[1]
	msg[14] = pidBuf[2]
	msg[15] = pidBuf[3]

	return msg
}

func receiveAndCheckOutput(server net.Conn, expected []byte, ch chan error) {
	defer close(ch)
	defer server.Close()

	buf := make([]byte, 4096)
	n, err := server.Read(buf)
	if err != nil {
		ch <- err
	}
	buf = buf[:n]

	// TODO Worth checking that the expected size is received, and that the Len field is correct?

	if !bytes.Equal(buf, expected) {
		ch <- fmt.Errorf("Expected %+v but got %+v instead", expected, buf)
	}
}

func TestSendingSADBDump(t *testing.T) {
	expected := []byte{2, 10, 0, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	expected = insertPidInMsg(expected)
	ch := make(chan error)
	server, client := net.Pipe()
	go receiveAndCheckOutput(server, expected, ch)

	p := PFKEY{socket: client}

	err := p.SendSADBDumpMsg()
	if err != nil {
		t.Errorf("Got error %+v when requesting SADB_DUMP", err)
	}

	for e := range ch {
		t.Error(e)
	}
}

func TestSendingSADBGETSPI(t *testing.T) {
	// We should probably load this data from a file instead
	expected := []byte{2, 1, 0, 3, 10, 0, 0, 0, 210, 4, 0, 0, 161, 46, 0, 0, 3, 0, 5, 0, 0, 32, 0, 0, 2, 0, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 6, 0, 0, 32, 0, 0, 2, 0, 0, 0, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 16, 0, 10, 0, 0, 0, 128, 150, 152, 0, 0, 0, 0, 0}
	expected = insertPidInMsg(expected)

	ch := make(chan error)
	server, client := net.Pipe()
	go receiveAndCheckOutput(server, expected, ch)

	p := PFKEY{socket: client}

	src := Node{Addr: net.IPv4(1, 2, 3, 4)}
	dst := Node{Addr: net.IPv4(5, 6, 7, 8)}

	err := p.SendSADBGETSPI(1234, src, dst)
	if err != nil {
		t.Error(err)
	}
	for e := range ch {
		t.Error(e)
	}
}

func TestSendingSADBREGISTER(t *testing.T) {
	// We should probably load this data from a file instead
	expected := []byte{2, 7, 0, 3, 2, 0, 0, 0, 0, 0, 0, 0, 111, 21, 0, 0}
	expected = insertPidInMsg(expected)

	ch := make(chan error)
	server, client := net.Pipe()
	go receiveAndCheckOutput(server, expected, ch)

	p := PFKEY{socket: client}

	err := p.SendSADBRegisterMsg()
	if err != nil {
		t.Error(err)
	}
	for e := range ch {
		t.Error(e)
	}
}

func TestReceiveSADBDump(t *testing.T) {
	ch := make(chan error)
	server, client := net.Pipe()
	go func() {
		defer server.Close()
		defer close(ch)

		buf := make([]byte, 4096)
		n, err := server.Read(buf)
		if err != nil {
			ch <- err
		}
		buf = buf[:n]

		// TODO: Compare buf to a well formed request?

		response := []byte{2, 10, 0, 3, 32, 0, 0, 0, 0, 0, 0, 0, 103, 10, 0, 0, 2, 0, 1, 0, 0, 30, 198, 170, 0, 1, 0, 12, 0, 0, 0, 0, 4, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 2, 0, 11, 0, 0, 0, 192, 2, 0, 0, 0, 0, 0, 0, 227, 179, 15, 89, 0, 0, 0, 0, 228, 179, 15, 89, 0, 0, 0, 0, 3, 0, 5, 0, 0, 32, 0, 0, 2, 0, 0, 0, 10, 0, 2, 7, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 6, 0, 0, 32, 0, 0, 2, 0, 0, 0, 10, 0, 2, 6, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 7, 0, 255, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 9, 0, 0, 1, 0, 0, 40, 141, 178, 141, 242, 74, 142, 67, 237, 231, 145, 81, 148, 10, 249, 253, 77, 164, 119, 141, 106, 73, 193, 49, 35, 84, 139, 157, 95, 216, 244, 48, 2, 0, 19, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

		server.Write(response)
	}()

	p := PFKEY{socket: client}

	err := p.SendSADBDumpMsg()
	if err != nil {
		t.Error(err)
	}

	msgs, err := p.RetrieveSADBDump()
	if err != nil {
		t.Fatal(err)
	}

	if len(msgs) != 1 {
		t.Fatalf("Expected to receive 1 message but got %d instead.", len(msgs))
	}

	expected := Msg{
		Msg: SADBMsg{
			Version: PF_KEY_V2,
			Len:     32,
			SAType:  SADB_SATYPE_ESP,
			Type:    10,
			PID:     2663,
		},
		Present: sadbExtensionsChecklist{
			SA:              true,
			LifetimeCurrent: true,
			LifetimeSoft:    true,
			LifetimeHard:    true,
			AddressSrc:      true,
			AddressDst:      true,
		},
		Extensions: sadbExtensions{
			SA: SADBSA{
				Len:     2,
				ExtType: 1,
				SPI:     2865110528,
				State:   SADB_SASTATE_MATURE,
				Encrypt: 12,
			},
			LifetimeHard: SADBLifetime{
				Len:     4,
				ExtType: 3,
			},

			LifetimeSoft: SADBLifetime{
				Len:     4,
				ExtType: 4,
			},
			LifetimeCurrent: SADBLifetime{
				Len:         4,
				ExtType:     2,
				Allocations: 11,
				Bytes:       704,
				Addtime:     1494201315,
				Usetime:     1494201316,
			},
			AddressSrc: SADBAddress{
				Len:       3,
				ExtType:   5,
				PrefixLen: 32,
			},
			SockAddrSrc: sockAddrIn{
				SinFamily: unix.AF_INET,
				SinAddr:   [4]byte{10, 0, 2, 7},
			},
			AddressDst: SADBAddress{
				Len:       3,
				ExtType:   6,
				PrefixLen: 32,
			},
			SockAddrDst: sockAddrIn{
				SinFamily: unix.AF_INET,
				SinAddr:   [4]byte{10, 0, 2, 6},
			},
		},
	}

	if err = compareMessages(expected, msgs[0]); err != nil {
		t.Error(err)
	}
}

func TestBuildFlush(t *testing.T) {
	expected := Msg{
		Msg: SADBMsg{
			Version: 2,
			Type:    SADB_FLUSH,
			SAType:  SADB_SATYPE_ESP,
			PID:     uint32(os.Getpid()),
		},
	}
	m := BuildSADBFLUSH()
	err := compareMessages(expected, m)
	if err != nil {
		t.Errorf("Error building SADB_FLUSH message: %s", err)
	}
}

func TestBuildDump(t *testing.T) {
	expected := Msg{
		Msg: SADBMsg{
			Version: PF_KEY_V2,
			Errno:   0,
			Type:    SADB_DUMP,
			SAType:  SADB_SATYPE_ESP,
			PID:     uint32(os.Getpid()),
		},
	}

	m := BuildSADBDUMPMsg()
	err := compareMessages(expected, m)
	if err != nil {
		t.Errorf("Error building SADB_DUMP message: %s", err)
	}
}

func TestReceiveEmptyDump(t *testing.T) {
	ch := make(chan error)
	server, client := net.Pipe()
	go func() {
		defer server.Close()
		defer close(ch)

		buf := make([]byte, 4096)
		n, err := server.Read(buf)
		if err != nil {
			ch <- err
		}
		buf = buf[:n]

		// TODO: Compare buf to a well formed request?

		response := []byte{2, 10, 2, 3, 2, 0, 0, 0, 0, 0, 0, 0, 147, 13, 0, 0}

		server.Write(response)

	}()

	p := PFKEY{socket: client}

	err := p.SendSADBDumpMsg()
	if err != nil {
		t.Error(err)
	}

	msgs, err := p.RetrieveSADBDump()
	if err != nil {
		t.Error(err)
	}

	if len(msgs) != 0 {
		t.Fatalf("Expected to receive 0 messages but got %d instead.", len(msgs))
	}

	/*
		// TODO: This should actually be a full PFKEYMsg
		expected := PFKEYMsg{
			Msg: SADBMsg{
				Version: PF_KEY_V2,
				Type:    SADB_DUMP,
				Errno:   2,
				SAType:  3,
				Len:     2,
				Seq:     0,
				PID:     uint32(os.Getpid()),
			},
		}

		if err = compareMessages(expected, msgs[0]); err != nil {
			t.Error(err)
		}
	*/
}
