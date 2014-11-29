package digest

import "fmt"

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
func Lrot64(x uint64, n int) uint64 {
	for i := 0; i < n; i++ {
		rbit := x & 0x8000000000000000
		x <<= 1
		rbit >>= 63
		x = x | rbit
	}

	return x
}

// Perform a left bitwise rotation of
// an 64 bit integer
func Lrot32(x uint32, n int) uint32 {
	for i := 0; i < n; i++ {
		rbit := x & 0x80000000
		x <<= 1
		rbit >>= 31
		x = x | rbit
	}
	return x
}

// Obtain the bytes of a uint64 number (Big-Endian)
func GetBytes32(x uint32) []byte {
	b := []byte{
		byte(x >> 24),
		byte(x >> 16),
		byte(x >> 8),
		byte(x),
	}

	return b
}

// Obtain the bytes of a uint32 number (Big-Endian)
func GetBytes64(x uint64) []byte {
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

// Obtain a int32 from the given byte slice
func GetInt32(b []byte) uint32 {
	i32 := uint32(b[3])
	for i := 2; i > 0; i-- {
		i32 <<= 8
		i32 = i32 | uint32(b[i])
	}

	return i32
}

// Perform a SHA1 message digest
func (sha SHA1) Digest(message []byte) []byte {
	var ml uint64 = uint64(len(message) * 8)

	fmt.Println("Length (Bit): ", ml)

	h0, h1, h2, h3, h4 := SHA_A, SHA_B, SHA_C, SHA_D, SHA_E

	fmt.Println("Message (No Bit 1)", message)
	message = append(message, 0x80)

	// Preprocessing; Pad the message with 0's until it
	// is congruent with 448 (mod 512)
	np := int((448 - (ml+8)%512) / 8)

	fmt.Printf("Padding: %d\n", np)
	fmt.Println("Message (No Padding)", message)

	for i := 0; i < np; i++ {
		message = append(message, 0x00)
	}
	fmt.Println("Message (Padding)", message)

	// Append the original message length as a 64 bit integer
	// Why 64? because 512 - 448 = 64, the remaining bits from the
	// preprocessing
	for _, b := range GetBytes64(ml + 1) {
		message = append(message, b)
	}

	fmt.Println("Message (With length)", message)
	fmt.Println("Message length: ", len(message)*8)

	for c := 0; c < len(message)/64; c++ {
		chunk := message[c : c+64]
		w := make([]uint32, 80)

		for i := 0; i < 80; i++ {
			if i < 16 {
				word := chunk[i : i+4]
				fmt.Println("Word: ", word)
				w[i] = GetInt32(word)
			} else {
				w[i] = Lrot32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)
			}
		}

		a, b, c, d, e := h0, h1, h2, h3, h4

		for i := 0; i < 80; i++ {
			var f, k uint32
			if between(i, 0, 19) {
				f = (b & c) | (^b & d)
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

			tmp := Lrot32(a, 5) + f + e + k + w[i]
			e = d
			d = c
			c = Lrot32(b, 30)
			b = a
			a = tmp
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e
	}

	// Obtain the bytes of each sub-hash
	var ib [][]byte = [][]byte{
		GetBytes32(h0),
		GetBytes32(h1),
		GetBytes32(h2),
		GetBytes32(h3),
		GetBytes32(h4),
	}

	hh := make([]byte, 20)
	for i, h := range ib {
		for j, b := range h {
			idx := (i*4 + j)
			hh[idx] = b
		}
	}

	return hh
}
