package pfkey

import (
	"bytes"
	"encoding/binary"
)

// GetSPI converts the SPI stored in the SADBSA from network order
// to machine order and returns it
func (s *SADBSA) GetSPI() uint32 {

	spiBuf := new(bytes.Buffer)
	var spi uint32

	binary.Write(spiBuf, binary.LittleEndian, s.SPI)
	binary.Read(spiBuf, binary.BigEndian, &spi)

	return spi
}

// writeStruct will write an arbitrary object into the underlying buffer inside a msgBuffer
func (b *msgBuffer) writeStruct(object interface{}) error {
	// TODO: Pay attention at how many bytes we managed to write
	msgBytes, err := getBytes(object)
	if err != nil {
		return err
	}
	_, err = b.buf.Write(msgBytes)

	return err
}

// writeBytes writes an arbitrary slice of bytes into the underlying buffer
func (b *msgBuffer) writeBytes(bts []byte) error {
	// TODO: Look at how many bytes we actually wrote
	_, err := b.buf.Write(bts)
	return err
}
