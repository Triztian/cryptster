package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
)

// Perform the cipher of the data that is obtained from the reader
func cipherText(reader io.Reader, cipher SimpleCipher, decode, verbose bool) []byte {
	var (
		data, results []byte
		read          int
		err           error
	)

	data = make([]byte, bytes.MinRead)
	results = make([]byte, 0)
	read = 0

	// Start reading the data, data is read into a byte array/slice
	// After the array has been populated, we need to encode/decode
	// each byte; that is done in the inner loop.
	// Create the buffer to hold data
	for err == nil || err != io.EOF || read > 0 {
		read, err = reader.Read(data)
		if err != nil {
			break
		}

		// Slice the trailing zeros if the data that was read is less
		// than `bytes.MinRead`
		data = data[0:read]

		printLn("Read "+fmt.Sprintf("%d", read)+" bytes", verbose)

		if IsTransposition(cipher) {
			printLn("Is transposition", verbose)
			cipher.SetPlaintext(data)
		}

		// After reading we encode or decode each byte
		for n := 0; n < read; n++ {
			var symbol, unit byte
			if IsTransposition(cipher) {
				unit = byte(n)
			} else {
				unit = data[n]
			}

			if decode {
				symbol = cipher.Decode(unit)
			} else {
				symbol = cipher.Encode(unit)
			}

			results = append(results, symbol)
		}
	}

	return results
}

// Perfom des3 ciphering
func des3(reader io.Reader, key []byte, decrypt, verbose bool) []byte {
	var (
		des3key, data, results []byte
	)

	des3key = append(des3key, key[:16]...)
	des3key = append(des3key, key[:8]...)

	if verbose {
		fmt.Println("DES3 Key", des3key)
	}

	des, err := NewTripleDESCipher(des3key)
	if err != nil {
		panic(err)
	}
	data = make([]byte, 128)
	results = make([]byte, 0)

	read, err := reader.Read(data)
	if read < 0 {
		return []byte{}
	}

	data = data[:read]
	if verbose {
		fmt.Println("Data: ", data)
	}

	for b := 0; b < int(len(data)/BlockSize); b++ {
		block := make([]byte, BlockSize)
		if decrypt {
			des.Decrypt(block, data[b:b+BlockSize])
		} else {
			des.Encrypt(block, data[b:b+BlockSize])
		}
		if verbose {
			fmt.Println("Block: ", b, block)
		}
		results = append(results, block...)
	}

	if verbose {
		fmt.Println("Results: ", results)
	}

	return results
}

// Create a hash from the data that is obtain from the reader
func hash(reader io.Reader, verbose bool) []byte {
	var (
		data, msg, results []byte
		read               int
		err                error
		sha                SHA
	)
	data = make([]byte, bytes.MinRead)
	results = make([]byte, bytes.MinRead)
	msg = make([]byte, 0)

	read, err = reader.Read(data)

	if verbose {
		fmt.Println("Read Data:", data)
		fmt.Println("Message: ", msg)
	}

	for read > 0 && err == nil {
		for i := 0; i < read; i++ {
			msg = append(msg, data[i])
		}

		if verbose {
			fmt.Println("SHA Message: ", msg)
		}
		read, err = reader.Read(data)
	}

	sha = SHA1{}
	results = sha.Digest(msg)

	return results
}

// Perform AES CBC 128 encryption
func aes128(reader io.Reader, key []byte, verbose bool) []byte {
	var (
		results   []byte
		plaintext []byte
		cipherkey [4][4]byte
	)

	plaintext = make([]byte, bytes.MinRead)

	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			cipherkey[i][j] = key[i*4+j]
		}
	}

	if verbose {
		fmt.Println("Key: ", cipherkey)
	}

	read, err := reader.Read(plaintext)
	if read > 0 && err == nil {
		results = aesCBC128(plaintext[:read], cipherkey)
	} else {
		panic("Could not read data.")
	}
	return results
}

func rsa(reader io.Reader, key []byte, decrypt, verbose bool) []byte {
	var (
		data, results []byte
	)

	data = make([]byte, bytes.MinRead)
	results = make([]byte, bytes.MinRead)

	bikey := big.NewInt(0)
	bikey = bikey.SetBytes(key)
	bigN := big.NewInt(N)
	read, err := reader.Read(data)
	if err != nil {
		panic(err)
	}
	if decrypt {
		results = RSAEncrypt(data[:read], bikey, bigN)
	} else {
		results = RSADecrypt(data[:read], bikey, bigN)
	}
	return results
}

func output(data []byte, filepath string) {
	err := ioutil.WriteFile(filepath, data, 0644)
	if err != nil {
		panic(err)
	}
}
