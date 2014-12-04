package main

const (
	SHA_A uint32 = 0x67452301
	SHA_B uint32 = 0xEFCDAB89
	SHA_C uint32 = 0x98BADCFE
	SHA_D uint32 = 0x10325476
	SHA_E uint32 = 0xC3D2E1F0

	// The K values used in the main loop
	K_0_19  uint32 = 0x5A827999
	K_20_39 uint32 = 0x6ED9EBA1
	K_40_59 uint32 = 0x8F1BBCDC
	K_60_79 uint32 = 0xCA62C1D6
)

type SHA interface {
	Digest(message []byte) []byte
}

type SHA1 struct{}

// Perform a SHA1 message digest
func (sha SHA1) Digest(message []byte) []byte {

	/*
		fmt.Println("SHA1 ---")
		fmt.Println("Message: ", message)
		fmt.Println("Message bit length: ", len(message)*8)
	*/

	var ml uint64 = uint64(len(message) * 8)

	h0, h1, h2, h3, h4 := SHA_A, SHA_B, SHA_C, SHA_D, SHA_E

	message = append(message, 0x80)

	// Preprocessing; Pad the message with 0's until it
	// is congruent with 448 (mod 512)
	np := int((448-ml%512)/8) - 1

	for i := 0; i < np; i++ {
		message = append(message, 0x00)
	}

	// Append the original message length as a 64 bit integer
	// Why 64? because 512 - 448 = 64, the remaining bits from the
	// preprocessing
	for _, b := range GetBytes64(ml) {
		message = append(message, b)
	}

	//fmt.Println("Message length: ", len(message))

	for c := 0; c < int((len(message)*8)/512); c++ {
		chunk := message[c : c+64]
		w := make([]uint32, 80)

		//fmt.Println("Chunk: ", chunk)

		a, b, c, d, e := h0, h1, h2, h3, h4

		for i := 0; i < 80; i++ {
			var f, k uint32

			if i < 16 {
				word := chunk[i*4 : i*4+4]
				w[i] = GetInt32(word)

			} else {
				w[i] = Lrot32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)

			}

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

			//fmt.Printf("Values: %d %x %x %x %x %x\n", i, a, b, c, d, e)
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

	//fmt.Println("Ib: ", ib)

	// Flatten the bytes of the hash vars into a single 20 byte array
	// to create the final hash value
	hh := make([]byte, 20)
	for i, h := range ib {
		for j, b := range h {
			idx := (i*4 + j)
			hh[idx] = b
		}
	}
	//fmt.Println("Digest: ", hh)
	return hh
}
