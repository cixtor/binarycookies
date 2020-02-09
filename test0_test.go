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

	if len(cook.pages) < index {
		t.Fatalf("page at index #%d is missing", index)
	}

	if cook.pages[index].Length != expected.Length {
		t.Fatalf("incorrect number of cookies at pages[%d]\n- %d\n+ %d", index, expected.Length, cook.pages[index].Length)
	}

	if len(cook.pages[index].Offsets) != len(expected.Offsets) {
		t.Fatalf("incorrect number of cookie offsets at pages[%d]\n- %#v\n+ %#v", index, expected.Offsets, cook.pages[index].Offsets)
	}

	for idx, offset := range expected.Offsets {
		if cook.pages[index].Offsets[idx] != offset {
			t.Fatalf("incorrect cookie offset at pages[%d]\n- %#v\n+ %#v\n! check index #%d", index, expected.Offsets, cook.pages[index].Offsets, idx)
		}
	}
}
