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
		args    arguments
		ciphers []string
		data    []byte
		read    int
		err     error
		cipher  Cipher
		text    string
	)
	args = initFlags()
	initCiphers(&ciphers)

	flag.Parse()
	printArgs(&args)

	data = make([]byte, bytes.MinRead)
	reader, err := getReader(&args)
	cipher = getCipher(&args)

	read, text = 0, ""
	for err == nil || err != io.EOF || read > 0 {
		read, err = reader.Read(data)
		if err != nil {
			break
		}

		printLn("Read "+fmt.Sprintf("%d", read)+" bytes", *args.Verbose)

		for n := 0; n < read; n++ {
			var symbol byte
			if *args.Decode {
				symbol = cipher.Decode(data[n])
			} else {
				symbol = cipher.Encode(data[n])
			}

			text += fmt.Sprintf("%c", symbol)

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

// Obtain the reader from where the data will be read
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

// Obtain a cipher given the arguments
func getCipher(args *arguments) Cipher {
	printLn("CipherArg: "+*args.Cipher, *args.Verbose)
	if *args.Cipher == "ROT13" {
		return ROTCipher{13}
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
		flag.String("c", "Plain", "The cipher that will be used to encode data"),
		flag.String("f", "", "The file path from where the data will be read."),
		flag.String("t", "", "The text to be ciphered/unciphered; as string"),
		flag.String("o", "", "The file path to where the output will be stored."),
	}

	return args
}

// Initialize the available cipher list
func initCiphers(ciphers *[]string) {
	ciphers = &[]string{
		"Plain",
		"ROT13",
	}
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
