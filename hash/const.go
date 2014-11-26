package hash

const (
	SHA_A uint8 = 0x67452301
	SHA_B uint8 = 0xEFCDAB89
	SHA_C uint8 = 0x98BADCFE
	SHA_D uint8 = 0x10325476
	SHA_E uint8 = 0xC3D2E1F0

	// The K values used in the main loop
	K_0_19  uint8 = 0x5A827999
	K_20_39 uint8 = 0x6ED9EBA1
	K_40_59 uint8 = 0x8F1BBCDC
	K_60_79 uint8 = 0xCA62C1D6
)

var K [4]uint8 = []uint8{K_0_19, K_20_39, K_40_59, K_60_79}
