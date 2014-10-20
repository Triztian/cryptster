package main

import (
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
	if *args.Verbose {
		printArgs(&args)
	}

	data = make([]byte, 1024)
	reader, err := getReader(&args)
	cipher = getCipher(&args)

	read, err, text = 0, nil, ""
	for err == nil || err != io.EOF || read > 0 {
		read, err = reader.Read(data)
		printLn("Read "+fmt.Sprintf("%d", read)+" bytes", *args.Verbose)

		for n := 0; n < read; n++ {
			var symbol byte
			if *args.Decode {
				symbol = cipher.Decode(data[n])
			} else {
				symbol = cipher.Encode(data[n])
			}

			text += fmt.Sprintf("%c", symbol)

			if *args.Verbose {
				fmt.Println("Encoding: ", strByte(data[n]), " --> ", strByte(symbol))
			}
		}
	}

	fmt.Println(text)

	if *args.Output != "" {
		reader = strings.NewReader(text)
		read, err = reader.Read(data)
		data = data[0:read]
		err = ioutil.WriteFile(*args.Output, data, 0644)
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
		flag.Bool("d", false, "Work in verbose mode."),
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
	fmt.Println("Version: ", *args.Version)
	fmt.Println("Verbose: ", *args.Verbose)
	fmt.Println("Decode: ", *args.Decode)
	fmt.Println("Cipher: ", *args.Cipher)
	fmt.Println("Text: ", *args.Text)
	fmt.Println("File: ", *args.File)
	fmt.Println("Output: ", *args.Output)
}

// Code and String representation of a byte
func strByte(b byte) string {
	return fmt.Sprintf("%d:%c", b, b)
}
