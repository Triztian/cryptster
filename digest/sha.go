package digest

import "math/big"

type SHA interface {
	Digest(message []byte) []byte
}

type SHA1 struct{}

func between(x, a, b int) bool {
	return a <= x && x <= b
}

func lrot(x, n uint64) uint64 {
	for i := 0; i < int(n); i++ {
		rbit := x & 0x80000000
		x <<= 1
		rbit >>= 64
		x = x & rbit
	}

	return x
}

func lrot32(x, n uint32) uint32 {
	for i := 0; i < int(n); i++ {
		rbit := x & 0x8000
		x <<= 1
		rbit >>= 32
		x = x & rbit
	}

	return x
}

func (sha SHA1) Digest(message []byte) []byte {
	var ml uint64 = uint64(len(message) * 8)

	message = append(message, 0x80)

	h0, h1, h2, h3, h4 := SHA_A, SHA_B, SHA_C, SHA_D, SHA_E

	np := int((512 - (ml+1)%512) / 8)
	for i := 0; i < np; i++ {
		message = append(message, byte(0x0))
	}

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
				w[i] = uint32(z.SetBytes(chunk).Uint64())
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

			tmp := (lrot(a, 5)) + f + e + k + uint64(w[i])
			e = d
			d = c
			c = lrot(b, 30)
			b = a
			a = tmp
		}

		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e
	}
	hh := (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
	ihh := big.NewInt(int64(hh))
	return ihh.Bytes()
}
