package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
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
}

func main() {
	var (
		args   arguments
		data   []byte
		read   int
		err    error
		cipher Cipher
		text   string
	)

	// Initialize the flag/cli arguments variable
	args = initFlags()

	flag.Parse()
	// Print the arguments if Verbose was enabled
	printArgs(&args)

	// Create the buffer to hold data
	data = make([]byte, bytes.MinRead)
	reader, err := getReader(&args)

	// Obtain the cipher based on the passed arguments
	cipher = getCipher(&args)

	// Start reading the data, data is read into a byte array/slice
	// After the array has been populated, we need to encode/decode
	// each byte; that is done in the inner loop.
	read, text = 0, ""
	for err == nil || err != io.EOF || read > 0 {
		read, err = reader.Read(data)
		if err != nil {
			break
		}

		// Slice the trailing zeros if the data that was read is less
		// than `bytes.MinRead`
		data = data[0:read]

		printLn("Read "+fmt.Sprintf("%d", read)+" bytes", *args.Verbose)

		if IsTransposition(cipher) {
			printLn("Is transposition", *args.Verbose)
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

			if *args.Decode {
				symbol = cipher.Decode(unit)
			} else {
				symbol = cipher.Encode(unit)
			}

			// Concatenate the character representation of the
			// processed symbol
			text += fmt.Sprintf("%c", symbol)

			// If verbose is set; print the processing of each symbol.
			printLn("Encoding: "+strByte(data[n])+" --> "+strByte(symbol), *args.Verbose)
		}
	}

	// If the Output flag is provided
	// it is stored in the specified file and not printed to stdout
	if *args.Output != "" {
		reader = strings.NewReader(text)
		read, err = reader.Read(data)
		if err != nil {
			data = data[0:read]
			err = ioutil.WriteFile(*args.Output, data, 0644)
		}
	} else {
		fmt.Println(text)
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
		fmt.Println("File: ", *args.File)
		fmt.Println("Output: ", *args.Output)
	}
}

// Code and String representation of a byte
func strByte(b byte) string {
	return fmt.Sprintf("%d:%c", b, b)
}
