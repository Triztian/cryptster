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
	Cipher  *string
	File    *string
}

func main() {
	var (
		args    arguments
		ciphers []string
		data    []byte
		read    int
		err     error
		cipher  Cipher
	)

	initFlags(&args)
	initCiphers(&ciphers)

	flag.Parse()
	data = make([]byte, 1024)
	reader := getReader(&args)
	cipher = getCipher(&args)

	read, err = reader.Read(data)
}

// Obtain the reader from where the data will be read
func getReader(args *arguments) io.Reader {
	var in io.Reader

	if isStdin() {
		fmt.Println("data from Stdin")
		in = os.Stdin
	} else {
		fmt.Println("data from Stdin")
		in = strings.NewReader("S3cr3t")
	}

	return in
}

func getCipher(args *arguments) Cipher {
	var cipher Cipher
	return cipher
}

// Determine if the data is obtained from Stdin or from an argument string
func isStdin() bool {
	var (
		in   io.Reader
		data []byte
		err  error
		read int
	)
	data = make([]byte, 100)
	in = os.Stdin
	read, err = in.Read(data)
	return err != nil
}

// Initialize the flags that the available on the CLI
func initFlags(args *arguments) {
	args = &arguments{
		flag.Bool("v", false, "Prints the current version of the program"),
		flag.String("c", "Plain", "The cipher that will be used to encode data"),
		flag.String("f", "-d", "The file path from where the data will be read."),
	}
}

// Initialize the available cipher list
func initCiphers(ciphers *[]string) {
	ciphers = &[]string{
		"Plain",
		"ROT13",
	}
}
