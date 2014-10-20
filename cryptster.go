package main

import (
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
	Cipher  *string
	File    *string
	Data    *string
}

func main() {
	fmt.Println("Cryptster Started")
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
	data = make([]byte, 1024)
	reader, err := getReader(&args)
	cipher = getCipher(&args)

	read, err, text = 0, nil, ""
	for err == nil || err != io.EOF || read > 0 {
		read, err = reader.Read(data)
		printLn("Read "+fmt.Sprintf("%d", read)+" bytes", *args.Verbose)
		for n := 0; n < read; n++ {
			ciphertext := cipher.Encode(data[n])
			text += strByte(ciphertext)
			if *args.Verbose {
				fmt.Println("Ciphertext: ", strByte(data[n]), " --> ", strByte(ciphertext))
			}
		}
	}
}

// Obtain the reader from where the data will be read
func getReader(args *arguments) (io.Reader, error) {
	if *args.Data != "" {
		printLn("Data from -d flag", *args.Verbose)
		return strings.NewReader(*args.Data), nil
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
		flag.String("c", "Plain", "The cipher that will be used to encode data"),
		flag.String("f", "", "The file path from where the data will be read."),
		flag.String("d", "", "The data to be ciphered, as string"),
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

func printLn(message string, verbose bool) {
	if verbose {
		fmt.Println(message)
	}
}

func printArgs(args *arguments) {
	fmt.Println("Version: ", *args.Version)
	fmt.Println("Verbose: ", *args.Verbose)
	fmt.Println("Cipher: ", *args.Cipher)
	fmt.Println("Data: ", *args.Data)
	fmt.Println("File: ", *args.File)
}

func strByte(b byte) string {
	return fmt.Sprintf("%d:%c", b, b)
}
