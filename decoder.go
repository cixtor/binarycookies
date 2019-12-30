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
	file     *os.File
	size     uint32
	page     []uint32
	pages    []Page
	checksum []byte
}

type Page struct {
	Valid   bool
	Length  uint32
	Offsets []uint32
	Cookies []Cookie
}

type Cookie struct {
	Size          uint32
	unknownOne    []byte
	Flags         uint32
	Secure        bool
	HttpOnly      bool
	unknownTwo    []byte
	domainOffset  uint32
	nameOffset    uint32
	pathOffset    uint32
	valueOffset   uint32
	commentOffset uint32
	Comment       []byte
	Domain        []byte
	Name          []byte
	Path          []byte
	Value         []byte
	Expiration    float64
	Creation      float64
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

// Decode reads the entire file, validates and returns all cookies.
func (b *BinaryCookies) Decode() ([]Page, error) {
	var err error

	if err = b.readPageSize(); err != nil {
		return nil, err
	}

	if err = b.readAllPages(); err != nil {
		return nil, err
	}

	for index := uint32(0); index < b.size; index++ {
		if err = b.readOnePage(index); err != nil {
			return nil, err
		}
	}

	if err = b.readChecksum(); err != nil {
		return nil, err
	}

	// NOTES(cixtor): optional extra bytes may exist after this point, these
	// bytes usually represent a Binary Property List (bplist00) and contain
	// a dictionary with additional information, for example, the cookie accept
	// policy for all tasks within sessions based on the website configuration.
	//
	// Example:
	//
	// $ hexdump -v -C Cookies.binarycookies
	// [...]
	// 00000000  62 70 6c 69 73 74 30 30  d1 01 02 5f 10 18 4e 53  |bplist00..._..NS|
	// 00000010  48 54 54 50 43 6f 6f 6b  69 65 41 63 63 65 70 74  |HTTPCookieAccept|
	// 00000020  50 6f 6c 69 63 79 10 02  08 0b 26 00 00 00 00 00  |Policy....&.....|
	// 00000030  00 01 01 00 00 00 00 00  00 00 03 00 00 00 00 00  |................|
	// 00000040  00 00 00 00 00 00 00 00  00 00 28                 |..........(|
	// 0000004b
	//
	// $ plutil -p Tail.plist
	// {
	//   "NSHTTPCookieAcceptPolicy" => 2
	// }

	return b.pages, nil
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

type cookieHelperFunction func(*Cookie) error

// readPageCookie reads and returns one cookie associated to a single page.
func (b *BinaryCookies) readPageCookie() (Cookie, error) {
	var err error
	var cookie Cookie

	functions := []cookieHelperFunction{
		b.readPageCookieSize,
		b.readPageCookieUnknownOne,
		b.readPageCookieFlags,
		b.readPageCookieUnknownTwo,
		b.readPageCookieDomainOffset,
	}

	for _, fun := range functions {
		if err = fun(&cookie); err != nil {
			return Cookie{}, err
		}
	}

	data := make([]byte, 4)

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie name offset %q -> %s", data, err)
	}

	cookie.nameOffset = binary.LittleEndian.Uint32(data)

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie path offset %q -> %s", data, err)
	}

	cookie.pathOffset = binary.LittleEndian.Uint32(data)

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie value offset %q -> %s", data, err)
	}

	cookie.valueOffset = binary.LittleEndian.Uint32(data)

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie comment offset %q -> %s", data, err)
	}

	cookie.commentOffset = binary.LittleEndian.Uint32(data)

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie end header %q -> %s", data, err)
	}

	if !bytes.Equal(data, []byte{0x0, 0x0, 0x0, 0x0}) {
		return Cookie{}, fmt.Errorf("readPageCookie invalid end header %q", data)
	}

	data = make([]byte, 8)

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie expiration date %q -> %s", data, err)
	}

	cookie.Expiration = math.Float64frombits(binary.LittleEndian.Uint64(data))

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie creation date %q -> %s", data, err)
	}

	cookie.Creation = math.Float64frombits(binary.LittleEndian.Uint64(data))

	if cookie.commentOffset > 0 {
		data = make([]byte, cookie.domainOffset-cookie.commentOffset)

		if _, err := b.file.Read(data); err != nil {
			return Cookie{}, fmt.Errorf("readPageCookie comment text %q -> %s", data, err)
		}

		cookie.Comment = data
	}

	data = make([]byte, cookie.nameOffset-cookie.domainOffset)

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie domain text %q -> %s", data, err)
	}

	cookie.Domain = data

	data = make([]byte, cookie.pathOffset-cookie.nameOffset)

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie name text %q -> %s", data, err)
	}

	cookie.Name = data

	data = make([]byte, cookie.valueOffset-cookie.pathOffset)

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie path text %q -> %s", data, err)
	}

	cookie.Path = data

	// NOTES(cixtor): read the remaining bytes corresponding to the current
	// cookie. The size of this slice of bytes is equal to the size of the
	// entire cookie minus the number of bytes we have read so far.
	data = make([]byte, cookie.Size-cookie.valueOffset)

	if _, err := b.file.Read(data); err != nil {
		return Cookie{}, fmt.Errorf("readPageCookie value text %q -> %s", data, err)
	}

	cookie.Value = data

	return cookie, nil
}

// readPageCookieSize reads and stores the cookie size.
func (b *BinaryCookies) readPageCookieSize(cookie *Cookie) error {
	data := make([]byte, 4)

	if _, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie size %q -> %s", data, err)
	}

	cookie.Size = binary.LittleEndian.Uint32(data)

	return nil
}

// readPageCookieUnknownOne reads and stores one of the unknown cookie fields.
func (b *BinaryCookies) readPageCookieUnknownOne(cookie *Cookie) error {
	data := make([]byte, 4)

	// NOTES(cixtor): unknown field that some people believe is related to the
	// cookie flags but so far no relevant articles online have been able to
	// confirm this claim. It may be possible to discover the purpose of these
	// bytes with some reverse engineering work on modern browsers.
	if _, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie unknown one %q -> %s", data, err)
	}

	cookie.unknownOne = data

	return nil
}

// readPageCookieFlags reads and stores the cookie flags.
func (b *BinaryCookies) readPageCookieFlags(cookie *Cookie) error {
	data := make([]byte, 4)

	// NOTES(cixtor): cookie flags: secure, httpOnly, sameSite.
	// - 0x0 = None
	// - 0x1 = Secure
	// - 0x4 = HttpOnly
	// - 0x5 = Secure+HttpOnly
	// Ref: https://en.wikipedia.org/wiki/HTTP_cookie#Terminology
	if _, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie flags %q -> %s", data, err)
	}

	cookie.Flags = binary.LittleEndian.Uint32(data)

	if cookie.Flags == 0x0 {
		cookie.Secure = false
		cookie.HttpOnly = false
	} else if cookie.Flags == 0x1 {
		cookie.Secure = true
	} else if cookie.Flags == 0x4 {
		cookie.HttpOnly = true
	} else if cookie.Flags == 0x5 {
		cookie.Secure = true
		cookie.HttpOnly = true
	}

	return nil
}

// readPageCookieUnknownTwo reads and stores one of the unknown cookie fields.
func (b *BinaryCookies) readPageCookieUnknownTwo(cookie *Cookie) error {
	data := make([]byte, 4)

	// NOTES(cixtor): unknown field that some people believe is related to the
	// cookie flags but so far no relevant articles online have been able to
	// confirm this claim. It may be possible to discover the purpose of these
	// bytes with some reverse engineering work on modern browsers.
	if _, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie unknown two %q -> %s", data, err)
	}

	cookie.unknownTwo = data

	return nil
}

// readPageCookieDomainOffset reads and stores the cookie domain offset.
func (b *BinaryCookies) readPageCookieDomainOffset(cookie *Cookie) error {
	data := make([]byte, 4)

	if _, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie domain offset %q -> %s", data, err)
	}

	cookie.domainOffset = binary.LittleEndian.Uint32(data)

	return nil
}

// readChecksum reads and stores the checksum of the entire file.
func (b *BinaryCookies) readChecksum() error {
	data := make([]byte, 8)

	if _, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readChecksum %s", err)
	}

	b.checksum = data

	return nil
}
