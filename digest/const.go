package digest

const (
	SHA_A uint64 = 0x67452301
	SHA_B uint64 = 0xEFCDAB89
	SHA_C uint64 = 0x98BADCFE
	SHA_D uint64 = 0x10325476
	SHA_E uint64 = 0xC3D2E1F0

	// The K values used in the main loop
	K_0_19  uint64 = 0x5A827999
	K_20_39 uint64 = 0x6ED9EBA1
	K_40_59 uint64 = 0x8F1BBCDC
	K_60_79 uint64 = 0xCA62C1D6
)
