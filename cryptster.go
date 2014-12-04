package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// This structure indicates the available
// flags on the CLI
type arguments struct {
	Version *bool
	Verbose *bool
	Decode  *bool
	Cipher  *string
	File    *string
	Text    *string
	Output  *string
	Key     *string
	Hash    *bool
}

func main() {
	var (
		args   arguments
		result []byte
		err    error
	)

	// Initialize the flag/cli arguments variable
	args = initFlags()

	flag.Parse()
	// Print the arguments if Verbose was enabled
	printArgs(&args)

	reader, err := getReader(&args)
	if err != nil {
		panic(err)
	}

	if *args.Hash {
		result = hash(reader, *args.Verbose)

	} else if *args.Cipher != "" {
		if *args.Cipher == "AESCBC128" {
			if *args.Key == "" {
				panic("Key is missing")

			} else {
				fmt.Println("Using Key: ", *args.Key)
				key := make([]byte, bytes.MinRead)
				ks := strings.NewReader(*args.Key)
				n, err := ks.Read(key)
				if err == nil && n >= 16 {
					result = aes128(reader, key[:n], *args.Verbose)
				} else {
					if n < 16 {
						panic(fmt.Sprintf("Key is less than 16 bytes (128 bits): %d", n))
					} else {
						panic(err)
					}
				}
			}
		} else {
			result = cipher(reader, getCipher(&args), *args.Decode, *args.Verbose)

		}
	}

	// If the Output flag is provided
	// it is stored in the specified file and not printed to stdout
	if *args.Output != "" {
		output(result, *args.Output)
	} else {
		if *args.Hash {
			fmt.Println(hex.EncodeToString(result))
		} else {
			fmt.Println(toString(result))
		}
	}
}

// Obtain the reader from where the data will be read.
// If the arguments specifias a file from where to read the data
// it is used instead of the -t argument value.
// Either way we return a io.Reader object whichs source is a file
// or a string.
func getReader(args *arguments) (io.Reader, error) {
	if *args.Text != "" && *args.File == "" {
		printLn("Data from -t flag", *args.Verbose)
		return strings.NewReader(*args.Text), nil

	} else if *args.File != "" {
		printLn("Data from -f flag", *args.Verbose)
		return os.Open(*args.File)

	} else {
		return nil, nil

	}
}

// Obtain a cipher given the arguments.
// Ciphers are mapped from a string to a "instance" of the
// cipher. New ciphers and their CLI values are defined here
func getCipher(args *arguments) Cipher {
	printLn("CipherArg: "+*args.Cipher, *args.Verbose)
	if *args.Cipher == "ROT13" {
		return ROTCipher{13}
	} else if *args.Cipher == "ROUTE" {
		return new(RouteCipher)
	} else {
		return PlainTextCipher{}
	}
}

// Initialize the flags that the available on the CLI
func initFlags() arguments {
	args := arguments{
		flag.Bool("v", false, "Prints the current version of the program"),
		flag.Bool("V", false, "Work in verbose mode."),
		flag.Bool("d", false, "Decode the string or file content using the specified cipher."),
		flag.String("c", "Plain", "The cipher that will be used to encode data: Plain, ROT13"),
		flag.String("f", "", "The file path from where the data will be read."),
		flag.String("t", "", "The text to be ciphered/unciphered; as string"),
		flag.String("o", "", "The file path to where the output will be stored."),
		flag.String("k", "", "The key to use for the given cipher"),
		flag.Bool("h", false, "Indicates if a SHA1 hash of the file or text"),
	}

	return args
}

// Print a line, based on the value of the verbose flag
func printLn(message string, verbose bool) {
	if verbose {
		fmt.Println(message)
	}
}

// Print the arguments of the program
func printArgs(args *arguments) {
	if *args.Verbose {
		fmt.Println("Version: ", *args.Version)
		fmt.Println("Verbose: ", *args.Verbose)
		fmt.Println("Decode: ", *args.Decode)
		fmt.Println("Cipher: ", *args.Cipher)
		fmt.Println("Text: ", *args.Text)
		fmt.Println("Hash: ", *args.Hash)
		fmt.Println("File: ", *args.File)
		fmt.Println("Output: ", *args.Output)
		fmt.Println("Key: ", *args.Key)
	}
}

// Code and String representation of a byte
func strByte(b byte) string {
	return fmt.Sprintf("%d:%c", b, b)
}

func toString(data []byte) string {
	// Concatenate the character representation of the
	// processed symbol
	text := ""
	for _, symbol := range data {
		text += fmt.Sprintf("%c", symbol)
	}

	return text
}
