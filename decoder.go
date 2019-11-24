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
	file  *os.File
	size  uint32
	page  []uint32
	pages []Page
}

type Page struct {
	Valid   bool
	Length  uint32
	Offsets []uint32
}

// New returns an instance of the Binary Cookies class.
func New(file *os.File) *BinaryCookies {
	return &BinaryCookies{file: file}
}

// Validate reads a number of bytes that are supposed to represent the magic
// number of valid binary cookies. If the file format is different then the
// function returns an error with some information.
func (b *BinaryCookies) Validate() error {
	data := make([]byte, 4)

	if _, err := b.file.Read(data); err != nil {
		return fmt.Errorf("Validate %q -> %s", data, err)
	}

	if !bytes.Equal(data, magic) {
		return fmt.Errorf("Validate invalid signature %q", data)
	}

	return nil
}

// readPageSize reads an integer representing the number of pages in the file.
func (b *BinaryCookies) readPageSize() error {
	data := make([]byte, 4)

	if _, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageSize %s", err)
	}

	b.size = binary.BigEndian.Uint32(data)

	return nil
}

// readAllPages reads the size for all pages in the file.
func (b *BinaryCookies) readAllPages() error {
	size := int(b.size)
	data := make([]byte, 4)

	b.page = make([]uint32, size)
	b.pages = make([]Page, size)

	for i := 0; i < size; i++ {
		if _, err := b.file.Read(data); err != nil {
			return fmt.Errorf("readAllPages %q -> %s", data, err)
		}

		b.page[i] = binary.BigEndian.Uint32(data)
	}

	return nil
}

// readOnePage reads one single page in the file.
func (b *BinaryCookies) readOnePage(idx uint32) error {
	data := make([]byte, 4)

	if _, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readOnePage page tag %q -> %s", data, err)
	}

	if !bytes.Equal(data, []byte{0x0, 0x0, 0x1, 0x0}) {
		return fmt.Errorf("readOnePage invalid page tag %q", data)
	}

	if _, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readOnePage number of cookies %q -> %s", data, err)
	}

	length := binary.LittleEndian.Uint32(data)
	offsets := make([]uint32, int(length))

	for i := 0; i < int(length); i++ {
		if _, err := b.file.Read(data); err != nil {
			return fmt.Errorf("readOnePage cookie offset %q -> %s", data, err)
		}

		offsets[i] = binary.LittleEndian.Uint32(data)
	}

	if _, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readOnePage page end %q -> %s", data, err)
	}

	if !bytes.Equal(data, []byte{0x0, 0x0, 0x0, 0x0}) {
		return fmt.Errorf("readOnePage invalid page end %q", data)
	}

	b.pages[idx] = Page{
		Valid:   true,
		Length:  length,
		Offsets: offsets,
	}

	return nil
}
