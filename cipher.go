package main

type Cipher interface {
	Encode(symbol byte) byte
	Decode(ciphertext byte) byte
}

// ROT13 Cipher to implement the Cipher interface
type ROT13Cipher struct{}

// Simple rotate function to implement the substitution
// It rotates the byte by 13
func (c ROT13Cipher) Encode(symbol byte) byte {
	return symbol + 13
}

// Simple decoding function for the ROT13 cipher
func (c ROT13Cipher) Decode(ciphertext byte) byte {
	return ciphertext - 13
}
