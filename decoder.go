package binarycookies

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

// magic are the bytes representing the signature of valid binary cookies.
var magic []byte = []byte{0x63, 0x6f, 0x6f, 0x6b}

// BinaryCookies is a struct representing relevant parts of the binary cookies
// archive. A couple of methods are available to read and validate the archive
// and to extract relevant information.
type BinaryCookies struct {
	file *os.File
	size uint32
	page []uint32
}

// New returns an instance of the Binary Cookies class.
func New(file *os.File) *BinaryCookies {
	return &BinaryCookies{file: file}
}

// ReadSignature reads a number of bytes that are supposed to represent the
// magic number of valid binary cookies. If the file format is different then
// the function returns an error with some information.
func (b *BinaryCookies) ReadSignature() error {
	data := make([]byte, 4)

	if _, err := b.file.Read(data); err != nil {
		return fmt.Errorf("ReadSignature %q -> %s", data, err)
	}

	if !bytes.Equal(data, magic) {
		return fmt.Errorf("ReadSignature invalid signature %q", data)
	}

	return nil
}

// IsValid returns True if the file signature matches valid binary cookies.
func (b *BinaryCookies) IsValid() bool {
	return b.ReadSignature() == nil
}

// ReadPageSize reads an integer representing the number of pages in the file.
func (b *BinaryCookies) ReadPageSize() error {
	data := make([]byte, 4)

	if _, err := b.file.Read(data); err != nil {
		return fmt.Errorf("ReadPageSize %s", err)
	}

	b.size = binary.BigEndian.Uint32(data)

	return nil
}

// ReadAllPages reads the size for all pages in the file.
func (b *BinaryCookies) ReadAllPages() error {
	size := int(b.size)
	data := make([]byte, 4)

	b.page = make([]uint32, size)

	for i := 0; i < size; i++ {
		if _, err := b.file.Read(data); err != nil {
			return fmt.Errorf("ReadAllPages %q -> %s", data, err)
		}

		b.page[i] = binary.BigEndian.Uint32(data)
	}

	return nil
}
