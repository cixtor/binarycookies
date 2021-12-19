package binarycookies

import (
	"bytes"
	"testing"
)

func FuzzTest(f *testing.F) {
	f.Add(_test1)
	f.Add(_test2)
	f.Add(_test3)
	f.Fuzz(func(t *testing.T, a []byte) {
		out, err := New(bytes.NewReader(a)).Decode()
		t.Logf("out: %#v\n", out)
		t.Logf("err: %s\n", err)
	})
}
