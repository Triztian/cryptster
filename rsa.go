package main

import "math/big"

const (
	MILLER_RABIN_COUNT int   = 10
	P                  int64 = 853
	Q                  int64 = 971
	N                  int64 = P * Q
	DELIM              byte  = 255
)

var (
	TWO  *big.Int = big.NewInt(2)
	ZERO *big.Int = big.NewInt(0)
	ONE  *big.Int = big.NewInt(1)
)

// Euler's PHI function
// http://intjforum.com/showthread.php?t=33068
// http://math.wikia.com/wiki/Euler%27s_totient_function
func phi(n, p, q int64) *big.Int {
	if n == 2 {
		return ZERO
	}

	var t, bn, i *big.Int
	bn = big.NewInt(n)

	if n < 0 {
		return bn.Abs(bn)
	}

	if n == 3 {
		return big.NewInt(n)
	}

	for i = big.NewInt(p); i.Cmp(bn) == -1; i = i.Add(i, TWO) {
		if bn.Mod(bn, i).Cmp(ZERO) == 0 && i.ProbablyPrime(MILLER_RABIN_COUNT) {
			one := big.NewInt(1)
			tmp := one.Sub(one, one.Div(one, big.NewInt(p)))
			t = t.Mul(t, tmp)
		}
	}

	return bn.Mul(bn, t)
}

func initPrimes() (int64, int64, int64) {
	return P, Q, N
}

// Compute the public key's exponent
func computeE(phiN *big.Int) *big.Int {
	e := ONE
	for ; e.Cmp(phiN) == -1; e = e.Add(e, ONE) {
		if ONE.Cmp(e.GCD(nil, nil, e, phiN)) == 0 {
			return e
		}
	}
	return e
}

// Compute the private key's exponent
func computeD(e, phiN *big.Int) *big.Int {
	return e.Exp(e, big.NewInt(-1), phiN)
}

func GenKeyPair() (*big.Int, *big.Int) {
	var e, d, phiN *big.Int
	phiN = phi(N, P, Q)
	e = computeE(phiN)
	return e, d
}

func Encrypt(data []byte, d, n *big.Int) []byte {
	msg := make([]byte, 0)
	for _, M := range data {
		m := big.NewInt(0)
		m = m.SetBytes([]byte{M})
		for _, b := range m.Exp(m, d, n).Bytes() {
			msg = append(msg, b)
		}
		msg = append(msg, DELIM)
	}
	return msg
}

func Decrypt(ciphertext []byte, e, n *big.Int) []byte {
	msg := make([]byte, 0)
	ic := big.NewInt(0)
	for _, c := range ciphertext {
		if c != DELIM {
			ic = ic.SetBytes(append(ic.Bytes(), c))
		} else {
			m := big.NewInt(0)
			m = m.SetBytes([]byte{c})
			m = ic.Exp(m, e, n)
			msg = append(msg, m.Bytes()[0])
		}
	}

	return msg
}
