package digest

import (
	"fmt"
	"math/big"
)

type SHA interface {
	Digest(message []byte) []byte
}

type SHA1 struct{}

// Determint if the given int is contained within
// the specified range
func between(x, a, b int) bool {
	return a <= x && x <= b
}

// Perform a left bitwise rotation of
// an 64 bit integer
func Lrot(x uint64, n int) uint64 {
	for i := 0; i < n; i++ {
		rbit := x & 0x8000000000000000
		x <<= 1
		rbit >>= 63
		x = x | rbit
	}

	return x
}

// Obtain the bytes of a uint64 number (Big-Endian)
func GetBytes(x uint64) []byte {
	b := []byte{
		byte(x >> 56),
		byte(x >> 48),
		byte(x >> 40),
		byte(x >> 32),
		byte(x >> 24),
		byte(x >> 16),
		byte(x >> 8),
		byte(x),
	}

	fmt.Printf("Bytes %x, ", x)
	return b
}

func (sha SHA1) Digest(message []byte) []byte {
	var ml uint64 = uint64(len(message) * 8)

	message = append(message, 0x80)

	h0, h1, h2, h3, h4 := SHA_A, SHA_B, SHA_C, SHA_D, SHA_E

	// Preprocessing; Pad the message with 0's until it
	// is congruent with 448 (mod 512)
	np := int((512 - (ml+1)%512) / 8)
	fmt.Printf("Padding: %d\n", np)
	fmt.Println("Message (No Padding)", message)
	for i := 0; i < np; i++ {
		message = append(message, byte(0x00))
	}
	fmt.Println("Message (Padding)", message)

	// Append the original message length as a 64 bit integer
	// Why 64? because 512 - 448 = 64, the remaining bits from the
	// preprocessing
	intb := big.NewInt(int64(ml))
	for _, b := range intb.Bytes() {
		message = append(message, b)
	}

	for c := 0; c < len(message)/64; c++ {
		chunk := message[c : c+64]
		z := big.NewInt(0)
		w := make([]uint32, 80)

		for i := 0; i < 16; i++ {
			if i < 16 {
				w[i] = uint32(z.SetBytes(chunk).Uint64() >> 32)
			} else {
				w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16])
			}
		}

		a, b, c, d, e := h0, h1, h2, h3, h4

		for i := 0; i < 79; i++ {
			var f, k uint64
			if between(i, 0, 19) {
				f = (a & b) | ((^b) & d)
				k = K_0_19

			} else if between(i, 20, 39) {
				f = b ^ c ^ d
				k = K_20_39

			} else if between(i, 40, 59) {
				f = (b & c) | (b & d) | (c & d)
				k = K_40_59

			} else if between(i, 60, 79) {
				f = b ^ c ^ d
				k = K_60_79

			}

			tmp := (Lrot(a, 5)) + f + e + k + uint64(w[i])
			e = d
			d = c
			c = Lrot(b, 30)
			b = a
			a = tmp
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e
	}
	var ib [][]byte = [][]byte{
		GetBytes(h0),
		GetBytes(h1),
		GetBytes(h2),
		GetBytes(h3),
		GetBytes(h4),
	}

	hh := make([]byte, 20)
	for i, h := range ib {
		for j, b := range h {
			idx := (i*5 + j)
			if idx > 19 {
				continue
			}
			fmt.Println("Idx: ", idx, i, j)
			hh[idx] = b
		}
	}

	return hh
}
