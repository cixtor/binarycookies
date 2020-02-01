package binarycookies

import (
	"io"
	"time"
)

// magic are the bytes representing the signature of valid binary cookies.
var magic []byte = []byte{0x63, 0x6f, 0x6f, 0x6b}

// timePadding is the Unix timestamp until Jan 2001 when Mac epoch starts.
var timePadding float64 = 978307200

// BinaryCookies is a struct representing relevant parts of the binary cookies
// archive. A couple of methods are available to read and validate the archive
// and to extract relevant information.
type BinaryCookies struct {
	file     io.Reader
	size     uint32
	page     []uint32
	pages    []Page
	checksum []byte
}

// Page represents a single web page and contains all the cookies associated
// to the same domain. A binary cookies archive contains all the cookies for
// all the pages the user has ever visited.
type Page struct {
	Length  uint32
	Offsets []uint32
	Cookies []Cookie
}

// Cookie or HTTP cookie is a small piece of data sent from a website and
// stored on the user's computer by the user's web browser while the user is
// browsing. Cookies were designed to be a reliable mechanism for websites to
// remember stateful information or to record the user's browsing activity.
//
// They can also be used to remember arbitrary pieces of information that the
// user previously entered into form fields such as names, addresses, passwords
// and credit-card numbers.
//
// The term "cookie" was coined by web-browser programmer Lou Montulli. It was
// derived from the term "magic cookie", which is a packet of data a program
// receives and sends back unchanged, used by Unix programmers.
//
// Ref: https://en.wikipedia.org/wiki/HTTP_cookie
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
	Expires       time.Time
	Creation      time.Time
}

// cookieHelperFunction defines a function signature to help readPageCookie
// read and process all the bytes associated to all the cookies found on each
// page. Each function takes a cookie pointer, allocates certain amount of
// memory, reads some bytes, runs some transformations and finally stores the
// decoded bytes into the cookie.
type cookieHelperFunction func(*Cookie) error

// New returns an instance of the Binary Cookies class.
func New(reader io.Reader) *BinaryCookies {
	return &BinaryCookies{file: reader}
}
