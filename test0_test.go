package binarycookies

import (
	"bytes"
	"testing"
)

func checkCookiePage(t *testing.T, data []byte, index int, expected Page) {
	cook := New(bytes.NewReader(data))

	if _, err := cook.Decode(); err != nil {
		t.Fatal(err)
	}
}
