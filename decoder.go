package binarycookies

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
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
	Cookies []Cookie
}

type Cookie struct {
	Size         uint32
	UnknownOne   []byte
	Flags        uint32
	UnknownTwo   []byte
	DomainOffset uint32
	NameOffset   uint32
	PathOffset   uint32
	ValueOffset  uint32
	DomainText   []byte
	NameText     []byte
	Expiration   float64
	Creation     float64
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
func (b *BinaryCookies) readOnePage(index uint32) error {
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

	cookies, err := b.readPageCookies(length)

	if err != nil {
		return err
	}

	b.pages[index] = Page{
		Valid:   true,
		Length:  length,
		Offsets: offsets,
		Cookies: cookies,
	}

	return nil
}

// readPageCookies reads and returns all cookies associated to a single page.
func (b *BinaryCookies) readPageCookies(length uint32) ([]Cookie, error) {
	cookies := make([]Cookie, length)

	for i := uint32(0); i < length; i++ {
		if cookie, err := b.readPageCookie(); err != nil {
			return []Cookie{}, err
		} else {
			cookies[i] = cookie
		}
	}

	return cookies, nil
}

// readPageCookie reads and returns one cookie associated to a single page.
func (b *BinaryCookies) readPageCookie() (Cookie, error) {
	var cookie Cookie

	data := make([]byte, 4)

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie size %q -> %s", data, err)
	}

	cookie.Size = binary.LittleEndian.Uint32(data)

	// NOTES(cixtor): unknown field that some people believe is related to the
	// cookie flags but so far no relevant articles online have been able to
	// confirm this claim. It may be possible to discover the purpose of these
	// bytes with some reverse engineering work on modern browsers.
	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie unknown one %q -> %s", data, err)
	}

	cookie.UnknownOne = data

	// NOTES(cixtor): cookie flags: secure, httpOnly, sameSite.
	// - 0x1 = Secure
	// - 0x2 = Unknown
	// - 0x4 = HttpOnly
	// - 0x5 = Secure+HttpOnly
	// Ref: https://en.wikipedia.org/wiki/HTTP_cookie#Terminology
	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie flags %q -> %s", data, err)
	}

	cookie.Flags = binary.LittleEndian.Uint32(data)

	// NOTES(cixtor): unknown field that some people believe is related to the
	// cookie flags but so far no relevant articles online have been able to
	// confirm this claim. It may be possible to discover the purpose of these
	// bytes with some reverse engineering work on modern browsers.
	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie unknown two %q -> %s", data, err)
	}

	cookie.UnknownTwo = data

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie domain offset %q -> %s", data, err)
	}

	cookie.DomainOffset = binary.LittleEndian.Uint32(data)

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie name offset %q -> %s", data, err)
	}

	cookie.NameOffset = binary.LittleEndian.Uint32(data)

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie path offset %q -> %s", data, err)
	}

	cookie.PathOffset = binary.LittleEndian.Uint32(data)

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie value offset %q -> %s", data, err)
	}

	cookie.ValueOffset = binary.LittleEndian.Uint32(data)

	data = make([]byte, 8)

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie end header %q -> %s", data, err)
	}

	if !bytes.Equal(data, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}) {
		return Cookie{}, fmt.Errorf("readPageCookie invalid end header %q", data)
	}

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie expiration date %q -> %s", data, err)
	}

	cookie.Expiration = math.Float64frombits(binary.LittleEndian.Uint64(data))

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie creation date %q -> %s", data, err)
	}

	cookie.Creation = math.Float64frombits(binary.LittleEndian.Uint64(data))

	data = make([]byte, cookie.NameOffset-cookie.DomainOffset)

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie domain text %q -> %s", data, err)
	}

	cookie.DomainText = data

	data = make([]byte, cookie.PathOffset-cookie.NameOffset)

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie name text %q -> %s", data, err)
	}

	cookie.NameText = data

	return cookie, nil
}
