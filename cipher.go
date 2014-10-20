package main

import "fmt"

const (
	CLASS_TRANSPOSITION = "transposition"
	CLASS_SUBSTITUTION  = "substitution"
)

// Convenience function to determine if the given cipher is a transposition
// cipher
func IsTransposition(cipher Cipher) bool {
	return cipher.Class() == CLASS_TRANSPOSITION
}

// Convenience function to determine fi the given cipher is a
// substitution
func IsSubstitution(cipher Cipher) bool {
	return cipher.Class() == CLASS_SUBSTITUTION
}

type Cipher interface {
	Class() string
	Encode(symbol byte) byte
	Decode(ciphertext byte) byte
	SetPlaintext(plaintext []byte)
}

// Plaintext cipher; no encoding; pass-through
type PlainTextCipher struct{}

func (p PlainTextCipher) Encode(symbol byte) byte {
	return symbol
}
func (p PlainTextCipher) Decode(ciphertext byte) byte {
	return ciphertext
}

// Defines the type of cipher
func (p PlainTextCipher) Class() string {
	return CLASS_SUBSTITUTION
}

func (p PlainTextCipher) SetPlaintext(plaintext []byte) {
	// do nothing
}

// ROT Cipher to implement the Cipher interface
// The rot cipher adds it's rotation to the encoded symbol
// and subtracts it to the decoded ciphertext
type ROTCipher struct {
	rotation byte
}

// Simple rotate function to implement the substitution
// It rotates the byte by it's rotation field
func (c ROTCipher) Encode(symbol byte) byte {
	return symbol + c.rotation
}

// Simple decoding function for the ROT cipher
func (c ROTCipher) Decode(ciphertext byte) byte {
	return ciphertext - c.rotation
}

func (c ROTCipher) Class() string {
	return CLASS_SUBSTITUTION
}

func (c ROTCipher) SetPlaintext(plaintext []byte) {
	// Do nothing
}

// The route cipher lays out the plaintext to be ciphered
// and rearranges them; essentially it maps one index into another.
// It's drawback is that it needs a reference to the complete plaintext
// which can be an incovenient in memory constrained devices.
//
// With a reference to the plaintext the symbol argument is
// treated as an index instead of the actual plaintext
// This implementation is a reverse route cipher
// Encoding and decoding is done in the same way
type RouteCipher struct {
	Plaintext []byte
}

func (c RouteCipher) Encode(symbol byte) byte {
	fmt.Println("Sym: ", int(symbol), "Len: ", len(c.Plaintext), "Plaintext: ", c.Plaintext)
	i := len(c.Plaintext) - int(symbol) - 1
	fmt.Println("i: ", i)
	return c.Plaintext[i]

}

func (c RouteCipher) Decode(symbol byte) byte {
	i := len(c.Plaintext) - int(symbol) - 1
	return c.Plaintext[i]
}

func (c RouteCipher) Class() string {
	return CLASS_TRANSPOSITION
}

func (c *RouteCipher) SetPlaintext(plaintext []byte) {
	c.Plaintext = make([]byte, len(plaintext))
	for i, b := range plaintext {
		c.Plaintext[i] = b
	}
}
