package main

// Determine if the given int is contained within
// the specified range
func between(x, a, b int) bool {
	return a <= x && x <= b
}

// Perform a left bitwise rotation of
// an 64 bit integer
func Lrot64(x uint64, n uint64) uint64 {
	return (x << n) | (x >> (64 - n))
}

// Perform a left bitwise rotation of
// an 64 bit integer
func Lrot32(x, n uint32) uint32 {
	return (x << n) | (x >> (32 - n))
}

// Obtain the bytes of a uint64 number (Big-Endian)
func GetBytes32(x uint32) []byte {
	return []byte{
		byte(x >> 24),
		byte(x >> 16),
		byte(x >> 8),
		byte(x),
	}
}

// Obtain the bytes of a uint32 number (Big-Endian)
func GetBytes64(x uint64) []byte {
	return []byte{
		byte(x >> 56),
		byte(x >> 48),
		byte(x >> 40),
		byte(x >> 32),
		byte(x >> 24),
		byte(x >> 16),
		byte(x >> 8),
		byte(x),
	}
}

// Obtain a int32 from the given byte slice
func GetInt32(b []byte) uint32 {
	i32 := uint32(b[0])
	for i := 1; i < 4; i++ {
		i32 <<= 8
		i32 = i32 | uint32(b[i])
	}

	return i32
}
