package main

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Triztian/cryptster/digest"
)

func TestIntConversion(t *testing.T) {
	var i64 uint64 = 0xFFFFFFFF00000000
	var i32 uint32 = 0xFFFFFFFF
	r := uint32(i64 >> 32)
	if r != i32 {
		t.Errorf("Unexpected int conversion, got %x expected %x", r, i32)
	}
}

// This test case verifies that the bit rotation is done properly
func TestLrot(t *testing.T) {
	var (
		x uint64 = 0x8000000080000000
		r uint64 = 0x0000000100000001
	)

	a := digest.Lrot(x, 1)
	if a != r {
		t.Errorf("Left Rotation incorrect got %x expected %x", a, r)
	}
}

func TestSHA(t *testing.T) {
	message := "The quick brown fox jumps over the lazy dog"
	hexString := "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
	dmsg := make([]byte, bytes.MinRead)

	sha := digest.SHA1{}
	reader := strings.NewReader(message)

	read, err := reader.Read(dmsg)
	if read > 0 && err == nil {
		computedHex := hex.EncodeToString(sha.Digest(dmsg[:read]))
		if computedHex != hexString {
			t.Errorf("Incorrect digest, should be \"%s\" but was \"%s\"", hexString, computedHex)
		}

		read, err = reader.Read(dmsg)
	} else {
		t.Error("Could not read data", err)
	}
}
