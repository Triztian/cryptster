package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
)

// Perform the cipher of the data that is obtained from the reader
func cipher(reader io.Reader, cipher Cipher, decode, verbose bool) []byte {
	var (
		data, results []byte
		read          int
		err           error
	)

	data = make([]byte, bytes.MinRead)
	results = make([]byte, bytes.MinRead)
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

func output(data []byte, filepath string) {
	err := ioutil.WriteFile(filepath, data, 0644)
	if err != nil {
		panic(err)
	}
}
