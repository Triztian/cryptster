package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestIntConversion(t *testing.T) {
	var i64 uint64 = 0xFFFFFFFF00000000
	var i32 uint32 = 0xFFFFFFFF
	r := uint32(i64 >> 32)
	if r != i32 {
		t.Errorf("Unexpected int conversion, got %x expected %x", r, i32)
	}
}

func TestGetBytes(t *testing.T) {
	var (
		x64 uint64 = 0xFFFFFFFF00000000
		b64 []byte = []byte{255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0}

		x32 uint32 = 0xFFFF0000
		b32 []byte = []byte{255, 255, 255, 255, 0, 0, 0, 0}
	)

	t.Skip()

	r64 := GetBytes64(x64)
	if !compareBytes(r64, b64) {
		t.Error("Incorrect byte extraction for uint64")
	}

	r32 := GetBytes32(x32)
	if !compareBytes(r32, b32) {
		t.Error("Incorrect byte extraction for uint32")
	}
}

//
func TestGetInts(t *testing.T) {
	var (
		b32 []byte = []byte{255, 255, 0, 0}
		x32 uint32 = 0xFFFF0000
	)

	r32 := GetInt32(b32)
	if r32 != x32 {
		t.Errorf("Incorrect byte conversion got \"%x\", expected \"%x\"", r32, x32)
	}
}

// Just to test the hex encoding
func TestEncode(t *testing.T) {
	var (
		b []byte = []byte{255, 255, 0, 0}
		s string = "ffff0000"
	)
	enc := hex.EncodeToString(b)
	if s != enc {
		t.Error("Encoding is different", s, enc)
	}
}

// This test case verifies that the bit rotation is done properly
func TestLrot(t *testing.T) {
	var (
		x64 uint64 = 0x8000000080000000
		r64 uint64 = 0x0000000100000001

		x32 uint32 = 0x80008000
		r32 uint32 = 0x00010001

		y32 uint32 = 0xF0F0F0F0
		s32 uint32 = 0x87878787
	)

	a64 := Lrot64(x64, 1)
	if a64 != r64 {
		t.Errorf("64-bit Left Rotation incorrect got %x expected %x", a64, r64)
	}

	a32 := Lrot32(x32, 1)
	if a32 != r32 {
		t.Errorf("32-bit Left Rotation incorrect got %x expected %x", a32, r32)
	}

	b32 := Lrot32(y32, 3)
	if b32 != s32 {
		t.Errorf("32-bit Left 3 Rotation incorrect got %x expected %x", b32, s32)
	}
}

func TestSHA(t *testing.T) {
	var messages = map[string]string{
		"A": "6dcd4ce23d88e2ee9568ba546c007c63d9131c1b",
		"The quick brown fox jumps over the lazy dog": "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
	}

	dmsg := make([]byte, bytes.MinRead)

	sha := SHA1{}
	for message, dig := range messages {
		reader := strings.NewReader(message)

		read, err := reader.Read(dmsg)
		if read > 0 && err == nil {
			computedHex := hex.EncodeToString(sha.Digest(dmsg[:read]))
			if computedHex != dig {
				t.Errorf("Incorrect digest SHA1(\"%s\") should be \"%s\" but was \"%s\"", message, dig, computedHex)
			}

			read, err = reader.Read(dmsg)
		} else {
			t.Error("Could not read data", err)
		}
	}
}

// Generate a random byte
func randByte() byte {
	rand.Seed(time.Now().UTC().UnixNano())
	return byte(rand.Int())
}

func TestAES(t *testing.T) {
	var (
		b   byte = 0xAF
		sbx byte = 0x08

		//s   string = "A"
		//key string = "secret"
	)

	sb := subByte(b)
	if sb != sbx {
		t.Errorf("Incorrect subByte for 0x%x, expected %x got %x", b, sbx, sb)
	}
}

func TestDES(t *testing.T) {
	// NewTripleDESCipher can also be used when EDE2 is required by
	// duplicating the first 8 bytes of the 16-byte key.
	ede2Key := []byte("Secreto de Redes")

	var tripleDESKey, plaintext, ciphertext, replaintext []byte
	tripleDESKey = append(tripleDESKey, ede2Key[:16]...)
	tripleDESKey = append(tripleDESKey, ede2Key[:8]...)

	des, err := NewTripleDESCipher(tripleDESKey)
	if err != nil {
		panic(err)
	}

	plaintext = make([]byte, 128)
	ciphertext = make([]byte, 128)
	replaintext = make([]byte, 128)

	for i := 0; i < 128; i++ {
		plaintext[i] = randByte()
	}

	// Decrypt the ciphertext in the same way that it was encrypted.
	for b := 0; b < int(len(plaintext)/BlockSize); b++ {
		cipherBlock := make([]byte, BlockSize)
		des.Encrypt(cipherBlock, plaintext[b:b+BlockSize])
		ciphertext = append(ciphertext, cipherBlock...)
	}

	// Decrypt the ciphertext in the same way that it was encrypted.
	for b := 0; b < int(len(ciphertext)/BlockSize); b++ {
		plainBlock := make([]byte, BlockSize)
		des.Decrypt(plainBlock, ciphertext[b:b+BlockSize])
		replaintext = append(replaintext, plainBlock...)
	}

	des.Encrypt(ciphertext, plaintext)
	des.Decrypt(replaintext, ciphertext)

	fmt.Println("\nPlaintext: ")
	fmt.Println(plaintext)

	fmt.Println("\nCiphertext: ")
	fmt.Println(ciphertext)

	fmt.Println("\nRecovered Plaintext: ")
	fmt.Println(replaintext)
}

func sum(a, b int) int {
	return a + b
}

func TestSum(t *testing.T) {
	var (
		a, b, r int = 10, 15, 25
	)

	x := sum(a, b)
	if x != r {
		t.Error("Incorrect sum")
	}
}
