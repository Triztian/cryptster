package main

import "fmt"

type Cipher interface {
	Encode(symbol byte) byte
	Decode(ciphertext byte) byte
}

// Plaintext cipher; no encoding
type PlainTextCipher struct{}

func (p PlainTextCipher) Encode(symbol byte) byte {
	return symbol
}
func (p PlainTextCipher) Decode(ciphertext byte) byte {
	return ciphertext
}

// ROT Cipher to implement the Cipher interface
type ROTCipher struct {
	rotation byte
}

// Simple rotate function to implement the substitution
// It rotates the byte by it's rotation field
func (c ROTCipher) Encode(symbol byte) byte {
	fmt.Println("Encoding", symbol)
	return symbol + c.rotation
}

// Simple decoding function for the ROT cipher
func (c ROTCipher) Decode(ciphertext byte) byte {
	return ciphertext - c.rotation
}
