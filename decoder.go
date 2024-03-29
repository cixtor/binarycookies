package binarycookies

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// Decode reads the entire file, validates and returns all cookies.
func (b *BinaryCookies) Decode() ([]Page, error) {
	if err := b.readSignature(); err != nil {
		return nil, err
	}

	if err := b.readPageSize(); err != nil {
		return nil, err
	}

	if err := b.readAllPages(); err != nil {
		return nil, err
	}

	for i := 0; i < int(b.size); i++ {
		if err := b.readOnePage(); err != nil {
			return nil, err
		}
	}

	if err := b.readChecksum(); err != nil {
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

// readSignature reads a number of bytes that are supposed to represent the
// magic number of valid binary cookies. If the file format is different then
// the function returns an error with some information.
func (b *BinaryCookies) readSignature() error {
	data := make([]byte, 4)

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readSignature %q; %w", data[:n], err)
	}

	if !bytes.Equal(data, magic) {
		return fmt.Errorf("readSignature invalid signature %q", data)
	}

	return nil
}

// readPageSize reads an integer representing the number of pages in the file.
func (b *BinaryCookies) readPageSize() error {
	data := make([]byte, 4)

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageSize from %q; %w", data[:n], err)
	}

	b.size = binary.BigEndian.Uint32(data)

	return nil
}

// readAllPages reads the size for all pages in the file.
func (b *BinaryCookies) readAllPages() error {
	size := int(b.size)
	data := make([]byte, 4)

	for i := 0; i < size; i++ {
		if n, err := b.file.Read(data); err != nil {
			return fmt.Errorf("readAllPages %q; %w", data[:n], err)
		}

		b.page = append(b.page, binary.BigEndian.Uint32(data))
	}

	return nil
}

// readOnePage reads one single page in the file.
func (b *BinaryCookies) readOnePage() error {
	data := make([]byte, 4)

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readOnePage page tag %q; %w", data[:n], err)
	}

	if !bytes.Equal(data, []byte{0x0, 0x0, 0x1, 0x0}) {
		return fmt.Errorf("readOnePage invalid page tag %q", data)
	}

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readOnePage number of cookies %q; %w", data[:n], err)
	}

	length := binary.LittleEndian.Uint32(data)
	offsets := make([]uint32, int(length))

	for i := 0; i < int(length); i++ {
		if n, err := b.file.Read(data); err != nil {
			return fmt.Errorf("readOnePage cookie offset %q; %w", data[:n], err)
		}

		offsets[i] = binary.LittleEndian.Uint32(data)
	}

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readOnePage page end %q; %w", data[:n], err)
	}

	if !bytes.Equal(data, []byte{0x0, 0x0, 0x0, 0x0}) {
		return fmt.Errorf("readOnePage invalid page end %q", data)
	}

	cookies, err := b.readPageCookies(length)

	if err != nil {
		return err
	}

	b.pages = append(b.pages, Page{
		Length:  length,
		Offsets: offsets,
		Cookies: cookies,
	})

	return nil
}

// readPageCookies reads and returns all cookies associated to a single page.
func (b *BinaryCookies) readPageCookies(length uint32) ([]Cookie, error) {
	var err error
	var cookie Cookie

	cookies := make([]Cookie, length)

	for i := uint32(0); i < length; i++ {
		if cookie, err = b.readPageCookie(); err != nil {
			return []Cookie{}, err
		}

		cookies[i] = cookie
	}

	return cookies, nil
}

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
		b.readPageCookieNameOffset,
		b.readPageCookiePathOffset,
		b.readPageCookieValueOffset,
		b.readPageCookieCommentOffset,
		b.readPageCookieEndHeader,
		b.readPageCookieExpires,
		b.readPageCookieCreation,
		b.checkCookieOverallSize,
		b.readPageCookieComment,
		b.readPageCookieDomain,
		b.readPageCookieName,
		b.readPageCookiePath,
		b.readPageCookieValue,
	}

	for _, fun := range functions {
		if err = fun(&cookie); err != nil {
			return Cookie{}, err
		}
	}

	return cookie, nil
}

// RFC 2965
// HTTP State Management Mechanism
// https://www.ietf.org/rfc/rfc2965.txt
//
// # Section 5.3 Implementation Limits
//
// Practical user agent implementations have limits on the number and
// size of cookies that they can store.  In general, user agents' cookie
// support should have no fixed limits.  They should strive to store as
// many frequently-used cookies as possible.  Furthermore, general-use
// user agents SHOULD provide each of the following minimum capabilities
// individually, although not necessarily simultaneously:
//
//   - at least 300 cookies
//
//   - at least 4096 bytes per cookie (as measured by the characters
//     that comprise the cookie non-terminal in the syntax description
//     of the Set-Cookie2 header, and as received in the Set-Cookie2
//     header)
//
//   - at least 20 cookies per unique host or domain name
//
// User agents created for specific purposes or for limited-capacity
// devices SHOULD provide at least 20 cookies of 4096 bytes, to ensure
// that the user can interact with a session-based origin server.
const maxCookieSize = 4096

func (b *BinaryCookies) checkCookieOverallSize(cookie *Cookie) error {
	var total uint32

	sizes := []uint32{
		/* Cookie Domain  */ (cookie.domainOffset - cookie.commentOffset),
		/* Cookie Name    */ (cookie.nameOffset - cookie.domainOffset),
		/* Cookie Path    */ (cookie.pathOffset - cookie.nameOffset),
		/* Cookie Value   */ (cookie.valueOffset - cookie.pathOffset),
		/* Cookie Comment */ (cookie.Size - cookie.valueOffset),
	}

	// Check if cookie component in case of uint overflow.
	for i, n := range sizes {
		if n > maxCookieSize {
			return fmt.Errorf("maximum cookie size exceeded in component[%d] (%d > 4096)", i, n)
		}

		total += n
	}

	if total > maxCookieSize {
		// Cookie Limitations
		//
		// Most browsers support cookies of up to 4096 bytes. Because of this
		// small limit, cookies are best used to store small amounts of data,
		// or better yet, an identifier such as a user ID. The user ID can
		// then be used to identify the user and read user information from a
		// database or other data store.
		//
		// http://msdn.microsoft.com/en-us/library/ms178194.aspx
		return fmt.Errorf("maximum overall cookie size exceeded %d > 4096", total)
	}

	return nil
}

// readPageCookieSize reads and stores the cookie size.
func (b *BinaryCookies) readPageCookieSize(cookie *Cookie) error {
	data := make([]byte, 4)

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie size %q; %w", data[:n], err)
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
	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie unknown one %q; %w", data[:n], err)
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
	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie flags %q; %w", data[:n], err)
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
	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie unknown two %q; %w", data[:n], err)
	}

	cookie.unknownTwo = data

	return nil
}

// readPageCookieDomainOffset reads and stores the cookie domain offset.
func (b *BinaryCookies) readPageCookieDomainOffset(cookie *Cookie) error {
	data := make([]byte, 4)

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie domain offset %q; %w", data[:n], err)
	}

	cookie.domainOffset = binary.LittleEndian.Uint32(data)

	return nil
}

// readPageCookieNameOffset reads and stores the cookie name offset.
func (b *BinaryCookies) readPageCookieNameOffset(cookie *Cookie) error {
	data := make([]byte, 4)

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie name offset %q; %w", data[:n], err)
	}

	cookie.nameOffset = binary.LittleEndian.Uint32(data)

	return nil
}

// readPageCookiePathOffset reads and stores the cookie path offset.
func (b *BinaryCookies) readPageCookiePathOffset(cookie *Cookie) error {
	data := make([]byte, 4)

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie path offset %q; %w", data[:n], err)
	}

	cookie.pathOffset = binary.LittleEndian.Uint32(data)

	return nil
}

// readPageCookieValueOffset reads and stores the cookie value offset.
func (b *BinaryCookies) readPageCookieValueOffset(cookie *Cookie) error {
	data := make([]byte, 4)

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie value offset %q; %w", data[:n], err)
	}

	cookie.valueOffset = binary.LittleEndian.Uint32(data)

	return nil
}

// readPageCookieCommentOffset reads and stores the cookie comment offset.
func (b *BinaryCookies) readPageCookieCommentOffset(cookie *Cookie) error {
	data := make([]byte, 4)

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie comment offset %q; %w", data[:n], err)
	}

	cookie.commentOffset = binary.LittleEndian.Uint32(data)

	return nil
}

// readPageCookieEndHeader reads and validates the cookie end header.
func (b *BinaryCookies) readPageCookieEndHeader(cookie *Cookie) error {
	data := make([]byte, 4)

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie end header %q; %w", data[:n], err)
	}

	if !bytes.Equal(data, []byte{0x0, 0x0, 0x0, 0x0}) {
		return fmt.Errorf("readPageCookie invalid end header %q", data)
	}

	return nil
}

// readPageCookieExpires reads and decodes the cookie expiration time.
func (b *BinaryCookies) readPageCookieExpires(cookie *Cookie) error {
	data := make([]byte, 8)

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie expiration time %q; %w", data[:n], err)
	}

	// NOTES(cixtor): convert Mac epoch time into a Unix timestamp.
	number := math.Float64frombits(binary.LittleEndian.Uint64(data))
	cookie.Expires = time.Unix(int64(number+timePadding), 0)

	return nil
}

// readPageCookieCreation reads and decodes the cookie creation time.
func (b *BinaryCookies) readPageCookieCreation(cookie *Cookie) error {
	data := make([]byte, 8)

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie creation time %q; %w", data[:n], err)
	}

	// NOTES(cixtor): convert Mac epoch time into a Unix timestamp.
	number := math.Float64frombits(binary.LittleEndian.Uint64(data))
	cookie.Creation = time.Unix(int64(number+timePadding), 0)

	return nil
}

// readPageCookieComment reads and stores the cookie comment field.
//
// Because cookies can contain private information about a user, the Cookie
// attribute allows an origin server to document its intended use of a cookie.
// The user can inspect the information to decide whether to initiate or
// continue a session with this cookie.
//
// Cookie comments are optional. If the comment offset is zero it means there
// are no comments in the file associated to the cookie we are decoding. This
// information is usually confused with the end cookie header which is always
// 0x00000000 but it is important to distinguish between these values to read
// the entire cookie data.
func (b *BinaryCookies) readPageCookieComment(cookie *Cookie) error {
	if cookie.commentOffset == 0 {
		return nil
	}

	data := make([]byte, cookie.domainOffset-cookie.commentOffset)

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie comment text %q; %w", data[:n], err)
	}

	cookie.Comment = data

	return nil
}

// readPageCookieDomain reads and stores the cookie domain field.
func (b *BinaryCookies) readPageCookieDomain(cookie *Cookie) error {
	data := make([]byte, cookie.nameOffset-cookie.domainOffset)

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie domain text %q; %w", data[:n], err)
	}

	// NOTES(cixtor): fix null-terminated string.
	cookie.Domain = data[0 : len(data)-1]

	return nil
}

// readPageCookieName reads and stores the cookie name field.
func (b *BinaryCookies) readPageCookieName(cookie *Cookie) error {
	data := make([]byte, cookie.pathOffset-cookie.nameOffset)

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie name text %q; %w", data[:n], err)
	}

	// NOTES(cixtor): fix null-terminated string.
	cookie.Name = data[0 : len(data)-1]

	return nil
}

// readPageCookiePath reads and stores the cookie path field.
func (b *BinaryCookies) readPageCookiePath(cookie *Cookie) error {
	data := make([]byte, cookie.valueOffset-cookie.pathOffset)

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie path text %q; %w", data[:n], err)
	}

	// NOTES(cixtor): fix null-terminated string.
	cookie.Path = data[0 : len(data)-1]

	return nil
}

// readPageCookieValue reads and stores the cookie value field.
func (b *BinaryCookies) readPageCookieValue(cookie *Cookie) error {
	data := make([]byte, cookie.Size-cookie.valueOffset)

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readPageCookie value text %q; %w", data[:n], err)
	}

	// NOTES(cixtor): fix null-terminated string.
	cookie.Value = data[0 : len(data)-1]

	return nil
}

// readChecksum reads and stores the checksum of the entire file.
func (b *BinaryCookies) readChecksum() error {
	data := make([]byte, 8)

	if n, err := b.file.Read(data); err != nil {
		return fmt.Errorf("readChecksum from %q; %w", data[:n], err)
	}

	b.checksum = data

	return nil
}
