package binarycookies

import (
	"os"
)

// BinaryCookies is a struct representing relevant parts of the binary cookies
// archive. A couple of methods are available to read and validate the archive
// and to extract relevant information.
type BinaryCookies struct {
	file *os.File
}

// New returns an instance of the Binary Cookies class.
func New(file *os.File) *BinaryCookies {
	return &BinaryCookies{file: file}
}
