package pfkey

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"path/filepath"
	"reflect"
	"testing"
)

var expectedMessages map[string]Msg

func init() {
	expectedMessages = make(map[string]Msg)
	expectedMessages["update_1"] = Msg{
		Msg: SADBMsg{
			Version: 2, Type: 6, Errno: 0, SAType: 3, Len: 11, Reserved: 0, Seq: 1, PID: 0,
		},
		Present: sadbExtensionsChecklist{
			AddressSrc: true,
			AddressDst: true,
			Proposal:   true,
			XPolicy:    true,
		},
		Extensions: sadbExtensions{
			AddressSrc: SADBAddress{
				Len:       3,
				ExtType:   5,
				PrefixLen: 32,
			},
			SockAddrSrc: sockAddrIn{
				SinFamily: 2,
				SinAddr:   [4]byte{10, 0, 2, 6},
			},
			AddressDst: SADBAddress{
				Len:       3,
				ExtType:   6,
				PrefixLen: 32,
			},
			SockAddrDst: sockAddrIn{
				SinFamily: 2,
				SinAddr:   [4]byte{10, 0, 2, 7},
			},
			Proposal: SADBProp{Len: 1, ExtType: 13, Replay: 32},
			XPolicy: SADBXPolicy{
				Len: 2, ExtType: 18, Type: 2, Dir: 2, Reserved: 0, ID: 89, Priority: 2147483648,
			},
		},
	}
	expectedMessages["registration_1"] = Msg{
		Msg: SADBMsg{
			Version: 2, Type: 7, SAType: 3, Len: 22, PID: 1509,
		},
		Present: sadbExtensionsChecklist{
			AuthAlgorithms:    true,
			EncryptAlgorithms: true,
		},
		Extensions: sadbExtensions{
			EncryptAlgorithms: []SADBAlg{
				SADBAlg{ID: 11, IVLen: 0, MinBits: 0, MaxBits: 0},
				SADBAlg{ID: 2, IVLen: 8, MinBits: 64, MaxBits: 64},
				SADBAlg{ID: 3, IVLen: 8, MinBits: 192, MaxBits: 192},
				SADBAlg{ID: 6, IVLen: 8, MinBits: 40, MaxBits: 128},
				SADBAlg{ID: 7, IVLen: 8, MinBits: 40, MaxBits: 448},
				SADBAlg{ID: 12, IVLen: 8, MinBits: 128, MaxBits: 256},
				SADBAlg{ID: 252, IVLen: 8, MinBits: 128, MaxBits: 256},
				SADBAlg{ID: 22, IVLen: 8, MinBits: 128, MaxBits: 256},
				SADBAlg{ID: 253, IVLen: 8, MinBits: 128, MaxBits: 256},
				SADBAlg{ID: 13, IVLen: 8, MinBits: 160, MaxBits: 288},
			},
			AuthAlgorithms: []SADBAlg{
				SADBAlg{ID: 251, IVLen: 0, MinBits: 0, MaxBits: 0},
				SADBAlg{ID: 2, IVLen: 0, MinBits: 128, MaxBits: 128},
				SADBAlg{ID: 3, IVLen: 0, MinBits: 160, MaxBits: 160},
				SADBAlg{ID: 5, IVLen: 0, MinBits: 256, MaxBits: 256},
				SADBAlg{ID: 6, IVLen: 0, MinBits: 384, MaxBits: 384},
				SADBAlg{ID: 7, IVLen: 0, MinBits: 512, MaxBits: 512},
				SADBAlg{ID: 8, IVLen: 0, MinBits: 160, MaxBits: 160},
				SADBAlg{ID: 9, IVLen: 0, MinBits: 128, MaxBits: 128},
			},
		},
	}
}

// compareMessages compares two PFKEYMsg and will return an error explaining the differences if differences are found.
func compareMessages(expected Msg, received Msg) error {

	if !reflect.DeepEqual(received.Msg, expected.Msg) {
		return fmt.Errorf("differences found in base message.\nExpected %+v\nBut got  %+v", expected.Msg, received.Msg)
	}

	if !reflect.DeepEqual(received.Present, expected.Present) {
		return fmt.Errorf("different extensions found.\nExpected %+v\nBut got  %+v instead", expected.Present, received.Present)
	}

	if !reflect.DeepEqual(expected.Extensions, received.Extensions) {
		return fmt.Errorf("differences found in extensions.\nExpected %+v\nBut got  %+v instead", expected.Extensions, received.Extensions)
	}
	return nil
}

func ReceiveAndExpectError(t *testing.T, name string, received []byte, expectedError error) {
	server, client := net.Pipe()
	go func() {
		server.Write(received)
		server.Close()
	}()
	p := PFKEY{socket: client}

	_, err := p.ReadMsg()
	if err != expectedError {
		t.Errorf("On test %q got %+v, expected %+v.", name, err, expectedError)
	}

}

func ReceivedAndExpectMessage(t *testing.T, name string, received []byte, expectedMsg Msg) {
	server, client := net.Pipe()
	go func() {
		server.Write(received)
		server.Close()
	}()

	p := PFKEY{socket: client}

	receivedMsg, err := p.ReadMsg()
	if err != nil {
		t.Errorf("On test %q got error %+v", name, err)
	}

	err = compareMessages(expectedMsg, receivedMsg)
	if err != nil {
		t.Errorf("On test %s: %s", name, err)
	}

}

func TestBasicMsgValidation(t *testing.T) {
	// TODO: Reenable tests once version and length validation have been added to ReadMsg
	//ReceiveAndExpectError(t, "invalid_version", []byte{3, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, errors.New("Invalid PF_KEY version"))
	//ReceiveAndExpectError(t, "invalid_len", []byte{2, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, errors.New("Invalid len field"))
}

func TestReceiveGarbageMsg(t *testing.T) {
	ReceiveAndExpectError(t, "short_msg", []byte{1, 23, 4, 5, 6, 7}, io.ErrUnexpectedEOF)
	ReceiveAndExpectError(t, "empty_msg", []byte{}, io.EOF)
}

func TestBasicMsgParsing(t *testing.T) {
	messagesFile := filepath.Join("test-fixtures", "messages.json")
	b, err := ioutil.ReadFile(messagesFile)
	if err != nil {
		t.Fatal(err)
	}

	// Load test fixture data
	var f interface{}
	err = json.Unmarshal(b, &f)
	m := f.(map[string]interface{})

	for k, v := range m {
		b, err := base64.RawStdEncoding.DecodeString(v.(string))
		if err != nil {
			t.Fatal(err)
		}
		ReceivedAndExpectMessage(t, k, b, expectedMessages[k])
	}
}

// TODO: Also create methods that allow us to *send* messages and check for the expected result on the other side.
